Luanti server list
====================

Setting up the webpage
----------------------

You will have to install node.js, doT.js and their dependencies to compile
the template files.

First install node.js, e.g.:

```sh
apt-get install nodejs
# OR:
yum install nodejs
```

Then install doT.js and its dependencies:

```sh
npm install dot "commander@11.1.0" mkdirp
```

And finally compile the template:

```sh
cd static
../node_modules/dot/bin/dot-packer -s .
```

You can now serve the webpage by copying the files in `static/` to your web root, or by [starting the server list](#setting-up-the-server).


Embedding the server list in a page
-----------------------------------

```html
<head>
	...
	<script>
		var master = {
			root: 'https://servers.luanti.org/',
			limit: 10,
			clients_min: 1,
			no_flags: true,
			no_ping: true,
			no_uptime: true
		};
	</script>
	...
</head>
<body>
	...
	<div id="server_list"></div>
	...
	<script defer src="https://servers.luanti.org/list.js"></script>
</body>
```

Setting up the server
---------------------

  1. Install Python 3 and pip:

```sh
apt-get install python3 python3-pip
# OR:
yum install python3 python3-pip
```

  2. Install required Python packages:

	pip3 install -r requirements.txt

  3. If using in production, install uwsgi and its python plugin:

```sh
apt-get install uwsgi-plugin-python3
# OR:
yum install uwsgi uwsgi-plugin-python3
```

  4. Configure the server by adding options to `config.py`.
     See `config-example.py` for defaults.

  5. Start the server:

```sh
# For development
./server.py

# For production:
uwsgi -s /run/serverlist.sock --plugins python3 -w server:app -T --threads 2
# then configure according to https://flask.palletsprojects.com/en/stable/deploying/uwsgi/
```

  7. (optional) Configure the proxy server, if any.  You should make the server
	 load static files directly from the static directory.  Also, `/list`
	 should be served from `list.json`.  Example for nginx:

```nginx
root /path/to/server/static;

rewrite ^/$ /index.html break;
rewrite ^/list$ /list.json break;

location = /list.json { expires 20s; }

try_files $uri @uwsgi;
location @uwsgi {
	include uwsgi_params;
	uwsgi_pass unix:/run/serverlist.sock;
}
```

Setting up the server (Apache version)
--------------------------------------

If you wish to use Apache to host the server list, do steps 1-2, 4, above.
Additionally install/enable mod_wsgi and an Apache site config like the following:

```ini
# This config assumes you have the server list at DocumentRoot.
# Visitors to the server list in this config would visit http://local.server/ and
# apache would serve up the output from server.py.

# Where are the serverlist files located?
DocumentRoot /var/games/luanti/serverlist

# Serve up server.py at the root of the URL.
WSGIScriptAlias / /var/games/luanti/serverlist/server.py

# The name of the function that we call when we invoke server.py
WSGICallableObject app

# These options are necessary to enable Daemon mode. Without this, you'll have strange behavior
# with servers dropping off your list! You can tweak threads as needed. See mod_wsgi documentation.
WSGIProcessGroup luanti-serverlist
WSGIDaemonProcess luanti-serverlist threads=2

<Directory /var/games/luanti/serverlist>
	Require all granted
</Directory>
```

License
-------

The Luanti server list code is licensed under the GNU Lesser General Public
License version 2.1 or later (LGPLv2.1+).  A LICENSE.txt file should have been
supplied with your copy of this software containing a copy of the license.
