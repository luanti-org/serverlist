#!/usr/bin/env python3
import os
import json
import time
import socket
from threading import Thread, RLock
from glob import glob

import maxminddb
from flask import Flask, request, send_from_directory, make_response


app = Flask(__name__, static_url_path = "")

# Load configuration
app.config.from_pyfile("config-example.py")  # Use example for defaults
if os.path.isfile(os.path.join(app.root_path, "config.py")):
	app.config.from_pyfile("config.py")

tmp = glob(os.path.join(app.root_path, "dbip-country-lite-*.mmdb"))
if tmp:
	reader = maxminddb.open_database(tmp[0], maxminddb.MODE_AUTO)
else:
	app.logger.warning(
		"For working GeoIP download the database from "+
		"https://db-ip.com/db/download/ip-to-country-lite and place the "+
		".mmdb file in the app root folder."
	)
	reader = None

# Helpers

# checkRequestAddress() error codes
ADDR_IS_PRIVATE      = 1
ADDR_IS_INVALID      = 2
ADDR_IS_INVALID_PORT = 3
ADDR_IS_UNICODE      = 4
ADDR_IS_EXAMPLE      = 5

ADDR_ERROR_HELP_TEXTS = {
	ADDR_IS_PRIVATE: "The server_address you provided is private or local. "
		"It is only reachable in your local network.\n"
		"If you meant to host a public server, adjust the setting and make sure your "
		"firewall is permitting connections (e.g. port forwarding).",
	ADDR_IS_INVALID: "The server_address you provided is invalid.\n"
		"If you don't have a domain name, try removing the setting from your configuration.",
	ADDR_IS_INVALID_PORT: "The server_address you provided is invalid.\n"
		"Note that the value must not include a port number.",
	ADDR_IS_UNICODE: "The server_address you provided includes Unicode characters.\n"
		"For domain names you have to use the punycode notation.",
	ADDR_IS_EXAMPLE: "The server_address you provided is an example value.",
}

def geoip_lookup_continent(ip):
	if ip.startswith("::ffff:"):
		ip = ip[7:]

	if not reader:
		return
	geo = reader.get(ip)

	if geo and "continent" in geo:
		return geo["continent"]["code"]
	else:
		app.logger.warning("Unable to get GeoIP continent data for %s.", ip)

# Views

@app.route("/")
def index():
	return app.send_static_file("index.html")


@app.route("/list")
def list_json():
	# We have to make sure that the list isn't cached for too long,
	# since it isn't really static.
	return send_from_directory(app.static_folder, "list.json", max_age=20)


@app.route("/geoip")
def geoip():
	continent = geoip_lookup_continent(request.remote_addr)

	resp = make_response({
		"continent": continent, # null on error
	})
	resp.cache_control.max_age = 7 * 86400
	resp.cache_control.private = True

	return resp


@app.post("/announce")
def announce():
	ip = request.remote_addr
	if ip.startswith("::ffff:"):
		ip = ip[7:]

	if ip in app.config["BANNED_IPS"]:
		return "Banned (IP).", 403

	data = request.form["json"]

	if len(data) > 8192:
		return "JSON data is too big.", 413

	try:
		server = json.loads(data)
	except json.JSONDecodeError:
		return "Unable to process JSON data.", 400

	if not isinstance(server, dict):
		return "JSON data is not an object.", 400

	action = server.get("action")
	if action not in ("start", "update", "delete"):
		return "Invalid action field.", 400

	server["ip"] = ip

	if not "port" in server:
		server["port"] = 30000
	#### Compatibility code ####
	# port was sent as a string instead of an integer
	elif isinstance(server["port"], str):
		server["port"] = int(server["port"])
	#### End compatibility code ####

	if "%s/%d" % (server["ip"], server["port"]) in app.config["BANNED_SERVERS"]:
		return "Banned (Server).", 403
	elif "address" in server and "%s/%d" % (server["address"].lower(), server["port"]) in app.config["BANNED_SERVERS"]:
		return "Banned (Server).", 403
	elif "address" in server and server["address"].lower() in app.config["BANNED_SERVERS"]:
		return "Banned (Server).", 403

	old = serverList.get(ip, server["port"])

	if action == "delete":
		if not old:
			return "Server not found."
		serverList.remove(old)
		serverList.save()
		return "Removed from server list."
	elif not checkRequestSchema(server):
		return "JSON data does not conform to schema.", 400
	elif not checkRequest(server):
		return "Incorrect JSON data.", 400

	if action == "update" and not old:
		if app.config["ALLOW_UPDATE_WITHOUT_OLD"]:
			action = "start"
		else:
			return "Server to update not found."

	# Since 'address' isn't the primary key it can change
	if action == "start" or old.get("address") != server.get("address"):
		err = checkRequestAddress(server)
		if err:
			return ADDR_ERROR_HELP_TEXTS[err], 400

	server["update_time"] = int(time.time())

	if action == "start":
		server["uptime"] = 0
		server["start"] = int(time.time())
	else:
		server["start"] = old["start"]

	server["clients_top"] = max(server["clients"], old["clients_top"]) if old else server["clients"]

	# Make sure that startup options are saved
	if action == "update":
		for field in ("dedicated", "rollback", "mapgen", "privs",
				"can_see_far_names", "mods"):
			if field in old:
				server[field] = old[field]

	# Popularity
	if old:
		server["updates"] = old["updates"] + 1
		# This is actually a count of all the client numbers we've received,
		# it includes clients that were on in the previous update.
		server["total_clients"] = old["total_clients"] + server["clients"]
	else:
		server["updates"] = 1
		server["total_clients"] = server["clients"]
	server["pop_v"] = server["total_clients"] / server["updates"]

	err = errorTracker.get(getErrorPK(server))

	finishRequestAsync(server)

	if err:
		warn, text = err
		if warn:
			text = ("Request has been filed and the previous one was successful, "
				"but take note:\n" + text)
		else:
			text = ("Request has been filed, "
				"but the previous request encountered the following error:\n" + text)
		return text, 409
	return "Request has been filed.", 202

# Utilities

# returns a primary key suitable for saving and replaying an error unique to a
# server that was announced.
def getErrorPK(server):
	# some failures depend on the client IP too
	return(server["ip"], server["address"], server["port"])

# check if something is a domain name (approximate)
def isDomain(s):
	return "." in s and s.rpartition(".")[2][0].isalpha()

# Returns ping time in seconds (up), False (down), or None (error).
def serverUp(info):
	sock = None
	try:
		sock = socket.socket(info[0], info[1], info[2])
		sock.settimeout(3)
		sock.connect(info[4])
		# send packet of type ORIGINAL, with no data
		#     this should prompt the server to assign us a peer id
		# [0] u32       protocol_id (PROTOCOL_ID)
		# [4] session_t sender_peer_id (PEER_ID_INEXISTENT)
		# [6] u8        channel
		# [7] u8        type (PACKET_TYPE_ORIGINAL)
		buf = b"\x4f\x45\x74\x03\x00\x00\x00\x01"
		sock.send(buf)
		start = time.monotonic()
		# receive reliable packet of type CONTROL, subtype SET_PEER_ID,
		#     with our assigned peer id as data
		# [0] u32        protocol_id (PROTOCOL_ID)
		# [4] session_t  sender_peer_id
		# [6] u8         channel
		# [7] u8         type (PACKET_TYPE_RELIABLE)
		# [8] u16        seqnum
		# [10] u8        type (PACKET_TYPE_CONTROL)
		# [11] u8        controltype (CONTROLTYPE_SET_PEER_ID)
		# [12] session_t peer_id_new
		data = sock.recv(1024)
		end = time.monotonic()
		if not data:
			return False
		peer_id = data[12:14]
		# send packet of type CONTROL, subtype DISCO,
		#     to cleanly close our server connection
		# [0] u32       protocol_id (PROTOCOL_ID)
		# [4] session_t sender_peer_id
		# [6] u8        channel
		# [7] u8        type (PACKET_TYPE_CONTROL)
		# [8] u8        controltype (CONTROLTYPE_DISCO)
		buf = b"\x4f\x45\x74\x03" + peer_id + b"\x00\x00\x03"
		sock.send(buf)
		return end - start
	except (socket.timeout, socket.error):
		return False
	except Exception as e:
		app.logger.warning("Unexpected exception during serverUp: %r", e)
		return None
	finally:
		if sock:
			sock.close()


def checkRequestAddress(server):
	name = server["address"].lower()

	# example value from minetest.conf
	EXAMPLE_TLDS = (".example.com", ".example.net", ".example.org")
	if name == "game.minetest.net" or any(name.endswith(s) for s in EXAMPLE_TLDS):
		return ADDR_IS_EXAMPLE

	# length limit for good measure
	if len(name) > 255:
		return ADDR_IS_INVALID
	# characters invalid in DNS names and IPs
	if any(c in name for c in " @#/*\"'\t\v\r\n\x00") or name.startswith("-"):
		return ADDR_IS_INVALID
	# if not ipv6, there must be at least one dot (two components)
	# Note: This is not actually true ('com' is valid domain), but we'll assume
	#       nobody who owns a TLD will ever host a Luanti server on the root domain.
	#       getaddrinfo also allows specifying IPs as integers, we don't want people
	#       to do that either.
	if ":" not in name and "." not in name:
		return ADDR_IS_INVALID

	if app.config["REJECT_PRIVATE_ADDRESSES"]:
		# private IPs (there are more but in practice these are 99% of cases)
		PRIVATE_NETS = ("10.", "192.168.", "127.", "0.")
		if any(name.startswith(s) for s in PRIVATE_NETS):
			return ADDR_IS_PRIVATE
		# reserved TLDs
		RESERVED_TLDS = (".localhost", ".local", ".internal")
		if name == "localhost" or any(name.endswith(s) for s in RESERVED_TLDS):
			return ADDR_IS_PRIVATE

	# ipv4/domain with port -or- ipv6 bracket notation
	if ("." in name and ":" in name) or (":" in name and "[" in name):
		return ADDR_IS_INVALID_PORT

	# unicode in hostname
	# Not sure about Python but the Luanti client definitely doesn't support it.
	if any(ord(c) > 127 for c in name):
		return ADDR_IS_UNICODE


# fieldName: (Required, Type, SubType)
fields = {
	"action": (True, "str"),

	"address": (False, "str"),
	"port": (False, "int"),

	"clients": (True, "int"),
	"clients_max": (True, "int"),
	"uptime": (True, "int"),
	"game_time": (True, "int"),
	"lag": (False, "float"),

	"clients_list": (False, "list", "str"),
	"mods": (False, "list", "str"),

	"version": (True, "str"),
	"proto_min": (True, "int"),
	"proto_max": (True, "int"),

	"gameid": (True, "str"),
	"mapgen": (False, "str"),
	"url": (False, "str"),
	"privs": (False, "str"),
	"name": (True, "str"),
	"description": (True, "str"),

	# Flags
	"creative": (False, "bool"),
	"dedicated": (False, "bool"),
	"damage": (False, "bool"),
	"pvp": (False, "bool"),
	"password": (False, "bool"),
	"rollback": (False, "bool"),
	"can_see_far_names": (False, "bool"),
}

def checkRequestSchema(server):
	for name, data in fields.items():
		if not name in server:
			if data[0]:
				return False
			continue
		#### Compatibility code ####
		if isinstance(server[name], str):
			# Accept strings in boolean fields but convert it to a
			# boolean, because old servers sent some booleans as strings.
			if data[1] == "bool":
				server[name] = server[name].lower() in ("true", "1")
				continue
			# Accept strings in integer fields but convert it to an
			# integer, for interoperability with e.g. core.write_json().
			if data[1] == "int":
				server[name] = int(server[name])
				continue
		#### End compatibility code ####
		if type(server[name]).__name__ != data[1]:
			return False
		if len(data) >= 3:
			for item in server[name]:
				if type(item).__name__ != data[2]:
					return False
	return True

def checkRequest(server):
	# check numbers
	for field in ("clients", "clients_max", "uptime", "game_time", "lag", "proto_min", "proto_max"):
		if field in server and server[field] < 0:
			return False

	if server["proto_min"] > server["proto_max"]:
		return False

	BAD_CHARS = " \t\v\r\n\x00\x27"

	# URL must be absolute and http(s)
	if "url" in server:
		url = server["url"]
		if not url or not any(url.startswith(p) for p in ["http://", "https://"]) or \
			any(c in url for c in BAD_CHARS):
			del server["url"]

	# reject funny business in client or mod list
	if "clients_list" in server:
		server["clients"] = len(server["clients_list"])
		for val in server["clients_list"]:
			if not val or any(c in val for c in BAD_CHARS):
				return False

	if "mods" in server:
		for val in server["mods"]:
			if not val or any(c in val for c in BAD_CHARS):
				return False

	# sanitize some text
	for field in ("gameid", "mapgen", "version", "privs"):
		if field in server:
			s = server[field]
			for c in BAD_CHARS:
				s = s.replace(c, "")
			server[field] = s

	# default value
	if "address" not in server or not server["address"]:
		server["address"] = server["ip"]

	return True


def finishRequestAsync(server):
	th = Thread(name = "ServerListThread",
		target = asyncFinishThread,
		args = (server,))
	th.start()


def asyncFinishThread(server):
	checkAddress = server["ip"] != server["address"]
	errorTracker.remove(getErrorPK(server))

	try:
		info = socket.getaddrinfo(server["address"],
			server["port"],
			type=socket.SOCK_DGRAM,
			proto=socket.SOL_UDP)
	except socket.gaierror:
		err = "Unable to get address info for %s" % server["address"]
		app.logger.warning(err)
		errorTracker.put(getErrorPK(server), (False, err))
		return

	if checkAddress:
		addresses = set(data[4][0] for data in info)
		have_v4 = any(d[0] == socket.AF_INET for d in info)
		have_v6 = any(d[0] == socket.AF_INET6 for d in info)
		if server["ip"] in addresses:
			pass
		elif (":" in server["ip"] and not have_v6) or ("." in server["ip"] and not have_v4):
			# If the client is ipv6 and there is no ipv6 on the domain (or the inverse)
			# then the check cannot possibly ever succeed.
			# Because this often happens accidentally just tolerate it.
			pass
		else:
			err = "Requester IP %s does not match host %s" % (server["ip"], server["address"])
			if isDomain(server["address"]):
				err += " (valid: %s)" % " ".join(addresses)
			app.logger.warning(err)
			# handle as warning
			errorTracker.put(getErrorPK(server), (True, err))

	geo = geoip_lookup_continent(info[-1][4][0])
	if geo:
		server["geo_continent"] = geo

	server["ping"] = serverUp(info[0])
	if not server["ping"]:
		err = "Server %s port %d did not respond to ping" % (server["address"], server["port"])
		if isDomain(server["address"]):
			err += " (tried %s)" % info[0][4][0]
		app.logger.warning(err)
		errorTracker.put(getErrorPK(server), (False, err))
		return

	# success!
	del server["action"]
	serverList.update(server)


class ServerList:
	def __init__(self):
		self.list = []
		self.maxServers = 0
		self.maxClients = 0
		self.lock = RLock()
		self.load()
		self.purgeOld()

	def getWithIndex(self, ip, port):
		with self.lock:
			for i, server in enumerate(self.list):
				if server["ip"] == ip and server["port"] == port:
					return (i, server)
		return (None, None)

	def get(self, ip, port):
		i, server = self.getWithIndex(ip, port)
		return server

	def remove(self, server):
		with self.lock:
			try:
				self.list.remove(server)
			except ValueError:
				pass

	def sort(self):
		def server_points(server):
			points = 0

			# 1 per client
			points += server["clients"]

			# Penalize highly loaded servers to improve player distribution.
			cap = int(server["clients_max"] * 0.80)
			if server["clients"] > cap:
				points -= server["clients"] - cap

			# 1 per month of age, limited to 8
			points += min(8, server["game_time"] / (60*60*24*30))

			# 1/2 per average client, limited to 4
			points += min(4, server["pop_v"] / 2)

			# -8 for unrealistic max_clients
			if server["clients_max"] > 200:
				points -= 8

			# -8 per second of ping over 0.4s
			if server["ping"] > 0.4:
				points -= (server["ping"] - 0.4) * 8

			# reduction to 40% for servers that support both legacy (v4) and v5 clients
			if server["proto_min"] <= 32 and server["proto_max"] > 36:
				points *= 0.4

			return points

		with self.lock:
			self.list.sort(key=server_points, reverse=True)

	def purgeOld(self):
		cutoff = int(time.time()) - app.config["PURGE_TIME"]
		with self.lock:
			count = len(self.list)
			self.list = [server for server in self.list if cutoff <= server["update_time"]]
			if len(self.list) < count:
				self.save()

	def load(self):
		with self.lock:
			try:
				with open(os.path.join(app.static_folder, "list.json"), "r", encoding="utf-8") as fd:
					data = json.load(fd)
			except FileNotFoundError:
				return

			if not data:
				return

			self.list = data["list"]
			self.maxServers = data["total_max"]["servers"]
			self.maxClients = data["total_max"]["clients"]

	def save(self):
		with self.lock:
			servers = len(self.list)
			clients = 0
			for server in self.list:
				clients += server["clients"]

			self.maxServers = max(servers, self.maxServers)
			self.maxClients = max(clients, self.maxClients)

			list_path = os.path.join(app.static_folder, "list.json")
			with open(list_path + "~", "w", encoding="utf-8") as fd:
				json.dump({
						"total": {"servers": servers, "clients": clients},
						"total_max": {"servers": self.maxServers, "clients": self.maxClients},
						"list": self.list
					},
					fd,
					indent = "\t" if app.config["DEBUG"] else None,
					separators = (', ', ': ') if app.config["DEBUG"] else (',', ':')
				)
			os.replace(list_path + "~", list_path)

	def update(self, server):
		with self.lock:
			i, old = self.getWithIndex(server["ip"], server["port"])
			if i is not None:
				self.list[i] = server
			else:
				self.list.append(server)

			self.sort()
			self.save()


class ErrorTracker:
	VALIDITY_TIME = 600

	def __init__(self):
		self.table = {}
		self.lock = RLock()

	def put(self, k, info):
		with self.lock:
			self.table[k] = (time.monotonic() + ErrorTracker.VALIDITY_TIME, info)

	def remove(self, k):
		with self.lock:
			self.table.pop(k, None)

	def get(self, k):
		with self.lock:
			e = self.table.get(k)
		if e and e[0] >= time.monotonic():
			return e[1]

	def cleanup(self):
		with self.lock:
			now = time.monotonic()
			table = {k: e for k, e in self.table.items() if e[0] >= now}
			self.table = table


class PurgeThread(Thread):
	def __init__(self):
		Thread.__init__(self, daemon=True)
	def run(self):
		while True:
			time.sleep(60)
			serverList.purgeOld()
			errorTracker.cleanup()


# Globals / Startup

serverList = ServerList()

errorTracker = ErrorTracker()

PurgeThread().start()

if __name__ == "__main__":
	app.run(host = app.config["HOST"], port = app.config["PORT"])
