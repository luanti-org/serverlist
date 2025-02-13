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

	json_data = request.form["json"]
	if len(json_data) > 8192:
		return "JSON data is too big.", 413

	try:
		req = json.loads(json_data)
	except json.JSONDecodeError:
		return "Unable to process JSON data.", 400

	if not isinstance(req, dict):
		return "JSON data is not an object.", 400

	action = req.pop("action", "")
	if action not in ("start", "update", "delete"):
		return "Invalid action field.", 400

	req["ip"] = ip

	if not "port" in req:
		req["port"] = 30000
	#### Compatibility code ####
	# port was sent as a string instead of an integer
	elif isinstance(req["port"], str):
		req["port"] = int(req["port"])
	#### End compatibility code ####

	if "%s/%d" % (req["ip"], req["port"]) in app.config["BANNED_SERVERS"]:
		return "Banned (Server).", 403
	elif "address" in req and "%s/%d" % (req["address"].lower(), req["port"]) in app.config["BANNED_SERVERS"]:
		return "Banned (Server).", 403
	elif "address" in req and req["address"].lower() in app.config["BANNED_SERVERS"]:
		return "Banned (Server).", 403

	old = serverList.get(ip, req["port"])

	if action == "delete":
		if not old:
			return "Server not found."
		serverList.remove(old)
		return "Removed from server list."

	if not checkRequestSchema(req):
		return "JSON data does not conform to schema.", 400
	elif not checkRequest(req):
		return "Incorrect JSON data.", 400

	if action == "update" and not old:
		if app.config["ALLOW_UPDATE_WITHOUT_OLD"] and req["uptime"] > 0:
			action = "start"
		else:
			return "Server to update not found."

	server = Server.from_request(req)

	# Since 'address' isn't the primary key it can change
	if action == "start" or old.address != server.address:
		err = checkRequestAddress(server)
		if err:
			return ADDR_ERROR_HELP_TEXTS[err], 400

	server.track_update(old, action == "update")

	err = errorTracker.get(server.get_error_pk())

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

# check if something is a domain name (approximate)
def isDomain(s):
	return "." in s and s.rpartition(".")[2][0].isalpha()

# Safely writes JSON data to a file
def dumpJsonToFile(filename, data):
	with open(filename + "~", "w", encoding="utf-8") as fd:
		json.dump(data, fd,
			indent = "\t" if app.config["DEBUG"] else None,
			separators = (',', ': ') if app.config["DEBUG"] else (',', ':')
		)
	os.replace(filename + "~", filename)

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
	name = server.address.lower()

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

def checkRequestSchema(req):
	for name, data in fields.items():
		if not name in req:
			if data[0]:
				return False
			continue
		#### Compatibility code ####
		if isinstance(req[name], str):
			# Accept strings in boolean fields but convert it to a
			# boolean, because old servers sent some booleans as strings.
			if data[1] == "bool":
				req[name] = req[name].lower() in ("true", "1")
				continue
			# Accept strings in integer fields but convert it to an
			# integer, for interoperability with e.g. core.write_json().
			if data[1] == "int":
				req[name] = int(req[name])
				continue
		#### End compatibility code ####
		if type(req[name]).__name__ != data[1]:
			return False
		if len(data) >= 3:
			for item in req[name]:
				if type(item).__name__ != data[2]:
					return False
	return True

def checkRequest(req):
	# check numbers
	for field in ("clients", "clients_max", "uptime", "game_time", "lag", "proto_min", "proto_max"):
		if field in req and req[field] < 0:
			return False

	if req["proto_min"] > req["proto_max"]:
		return False

	BAD_CHARS = " \t\v\r\n\x00\x27"

	# URL must be absolute and http(s)
	if "url" in req:
		url = req["url"]
		if not url or not any(url.startswith(p) for p in ["http://", "https://"]) or \
			any(c in url for c in BAD_CHARS):
			del req["url"]

	# reject funny business in client or mod list
	if "clients_list" in req:
		req["clients"] = len(req["clients_list"])
		for val in req["clients_list"]:
			if not val or any(c in val for c in BAD_CHARS):
				return False

	if "mods" in req:
		for val in req["mods"]:
			if not val or any(c in val for c in BAD_CHARS):
				return False

	# sanitize some text
	for field in ("gameid", "mapgen", "version", "privs"):
		if field in req:
			s = req[field]
			for c in BAD_CHARS:
				s = s.replace(c, "")
			req[field] = s

	# default value
	if "address" not in req or not req["address"]:
		req["address"] = req["ip"]

	return True


def finishRequestAsync(server):
	th = Thread(name = "ServerListThread",
		target = asyncFinishThread,
		args = (server,))
	th.start()


def asyncFinishThread(server: 'Server'):
	errorTracker.remove(server.get_error_pk())

	try:
		info = socket.getaddrinfo(server.address,
			server.port,
			type=socket.SOCK_DGRAM,
			proto=socket.SOL_UDP)
	except socket.gaierror:
		err = "Unable to get address info for %s" % server.address
		app.logger.warning(err)
		errorTracker.put(server.get_error_pk(), (False, err))
		return

	if server.ip == server.address:
		server.verifyLevel = 3
	else:
		addresses = set(data[4][0] for data in info)
		have_v4 = any(d[0] == socket.AF_INET for d in info)
		have_v6 = any(d[0] == socket.AF_INET6 for d in info)
		if server.ip in addresses:
			server.verifyLevel = 3
		elif (":" in server.ip and not have_v6) or ("." in server.ip and not have_v4):
			# If the client is ipv6 and there is no ipv6 on the domain (or the inverse)
			# then the check cannot possibly ever succeed.
			# Because this often happens accidentally just tolerate it.
			server.verifyLevel = 2
		else:
			err = "Requester IP %s does not match host %s" % (server.ip, server.address)
			if isDomain(server.address):
				err += " (valid: %s)" % " ".join(addresses)
			app.logger.warning(err)
			# handle as warning
			errorTracker.put(server.get_error_pk(), (True, err))
			server.verifyLevel = 1

	# do this here since verifyLevel is now set
	if serverList.checkDuplicate(server):
		err = "Server %s port %d already exists on the list" % (server.address, server.port)
		app.logger.warning(err)
		errorTracker.put(server.get_error_pk(), (False, err))
		return

	geo = geoip_lookup_continent(info[-1][4][0])
	if geo:
		server.meta["geo_continent"] = geo

	ping = serverUp(info[0])
	if not ping:
		err = "Server %s port %d did not respond to ping" % (server.address, server.port)
		if isDomain(server.address):
			err += " (tried %s)" % info[0][4][0]
		app.logger.warning(err)
		errorTracker.put(server.get_error_pk(), (False, err))
		return
	server.meta["ping"] = round(ping, 5)

	# success!
	serverList.update(server)


# represents a single server on the list
class Server:
	PROPS = ("startTime", "updateCount", "updateTime", "totalClients", "verifyLevel")

	def __init__(self, ip: str, port: str, address: str, meta: dict):
		# IP of announce requester (PRIMARY KEY)
		self.ip = ip
		# port of server (PRIMARY KEY)
		self.port = port
		# connectable domain or IP
		self.address = address
		# public metadata
		self.meta = meta
		# unix time of first update
		self.startTime = 0
		# number of updates received
		self.updateCount = 0
		# unix time of last update received
		self.updateTime = 0
		# total clients counted over all updates
		self.totalClients = 0
		# how well the IP verification was passed (bigger is better)
		self.verifyLevel = 0

	# creates an instance from the data of an announce request
	@classmethod
	def from_request(cls, data):
		ip = data["ip"]
		port = data["port"]
		address = data["address"]
		for k in ("ip", "port", "address", "action"):
			data.pop(k, 0)
		return cls(ip, port, address, data)

	# creates an instance from persisted data
	@classmethod
	def from_storage(cls, data):
		p = data.pop()
		obj = cls(*data)
		for k in cls.PROPS:
			if k in p:
				setattr(obj, k, p[k])
		return obj

	# returns data to persist
	def to_storage(self):
		p = {k: getattr(self, k) for k in self.PROPS}
		return (self.ip, self.port, self.address, self.meta, p)

	# returns server dict intended for public list
	def to_list_json(self):
		ret = self.meta.copy()
		ret["address"] = self.address
		ret["port"] = self.port
		ret["pop_v"] = self.get_average_clients()
		return ret

	# returns a primary key suitable for saving and replaying an error unique to a
	# server that was announced.
	def get_error_pk(self):
		# some failures depend on the client IP too
		return (self.ip, self.port, self.address)

	def get_average_clients(self):
		if self.updateCount:
			return round(self.totalClients / self.updateCount)
		return 0

	def track_update(self, old: 'Server', is_update: bool):
		# this might look a bit strange, but once a `Server` object is put into
		# list it becomes immutable since it's under lock. So we have to copy
		# stuff we need from the old object, and then replace it later.
		assert old or not is_update
		self.startTime = old.startTime if old else int(time.time())
		self.updateTime = int(time.time())

		# Make sure that startup options are saved
		if is_update:
			for field in ("dedicated", "rollback", "mapgen", "privs",
					"can_see_far_names", "mods"):
				if field in old.meta:
					self.meta[field] = old.meta[field]
		else:
			self.meta["uptime"] = 0

		# Popularity
		if old:
			self.updateCount = old.updateCount + 1
			self.totalClients += self.meta["clients"]
			self.meta["clients_top"] = max(self.meta["clients"], old.meta["clients_top"])
		else:
			self.updateCount = 1
			self.meta["clients_top"] = self.totalClients = self.meta["clients"]

	# check if this server is a logical duplicate of the other one.
	def is_duplicate(self, other: 'Server'):
		if self.port == other.port and self.address.lower() == other.address.lower():
			# if everything matches it's not a duplicate but literally the same
			if self.ip == other.ip:
				return False
			# we have a duplicate but the more trusted one gets to stay
			return self.verifyLevel < other.verifyLevel
		return False


# Represents an ordered list of server instances as well as methods
# to persist it.
class ServerList:
	def __init__(self):
		self.list = []
		self.maxServers = 0
		self.maxClients = 0
		self.storagePath = os.path.join(app.root_path, "store.json")
		self.publicPath = os.path.join(app.static_folder, "list.json")
		self.lock = RLock()
		self.load()
		self.purgeOld()

	def getWithIndex(self, ip, port):
		with self.lock:
			for i, server in enumerate(self.list):
				if server.ip == ip and server.port == port:
					return (i, server)
		return (None, None)

	def get(self, ip, port):
		i, server = self.getWithIndex(ip, port)
		return server

	def checkDuplicate(self, other_server):
		with self.lock:
			for server in self.list:
				if server.is_duplicate(other_server):
					return True
		return False

	def remove(self, server):
		with self.lock:
			try:
				self.list.remove(server)
			except ValueError:
				return
			self.save()
			self.savePublic()

	def sort(self):
		def server_points(server: Server):
			points = 0
			meta = server.meta

			# 1 per client
			points += meta["clients"]

			# Penalize highly loaded servers to improve player distribution.
			cap = int(meta["clients_max"] * 0.80)
			if meta["clients"] > cap:
				points -= meta["clients"] - cap

			# 1 per month of age, limited to 8
			points += min(8, meta["game_time"] / (60*60*24*30))

			# 1/2 per average client, limited to 4
			points += min(4, server.get_average_clients() / 2)

			# -8 for unrealistic max_clients
			if meta["clients_max"] > 200:
				points -= 8

			# -8 per second of ping over 0.4s
			if meta["ping"] > 0.4:
				points -= (meta["ping"] - 0.4) * 8

			# reduction to 60% for servers that support both legacy (v4) and v5 clients
			if meta["proto_min"] <= 32 and meta["proto_max"] > 36:
				points *= 0.6

			return points

		with self.lock:
			self.list.sort(key=server_points, reverse=True)

	def purgeOld(self):
		cutoff = int(time.time()) - app.config["PURGE_TIME"]
		with self.lock:
			count = len(self.list)
			self.list = [server for server in self.list if cutoff <= server.updateTime]
			if len(self.list) < count:
				self.save()
				self.savePublic()

	def load(self):
		# TODO?: this is a poor man's database. maybe we should use sqlite3?
		with self.lock:
			try:
				with open(self.storagePath, "r", encoding="utf-8") as fd:
					data = json.load(fd)
			except FileNotFoundError:
				return

			if not data:
				return

			self.list = list(Server.from_storage(x) for x in data["list"])
			self.maxServers = data["maxServers"]
			self.maxClients = data["maxClients"]

	def save(self):
		with self.lock:
			out_list = list(server.to_storage() for server in self.list)
			dumpJsonToFile(self.storagePath, {
				"list": out_list,
				"maxServers": self.maxServers,
				"maxClients": self.maxClients
			})

	def savePublic(self):
		with self.lock:
			out_list = []
			servers = len(self.list)
			clients = 0
			for server in self.list:
				out_list.append(server.to_list_json())
				clients += server.meta["clients"]

			self.maxServers = max(servers, self.maxServers)
			self.maxClients = max(clients, self.maxClients)

			dumpJsonToFile(self.publicPath, {
				"total": {"servers": servers, "clients": clients},
				"total_max": {"servers": self.maxServers, "clients": self.maxClients},
				"list": out_list
			})

	def update(self, server):
		with self.lock:
			i, old = self.getWithIndex(server.ip, server.port)
			if i is not None:
				self.list[i] = server
			else:
				self.list.append(server)

			self.sort()
			self.save()
			self.savePublic()


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
