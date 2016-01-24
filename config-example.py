from datetime import timedelta

# Enables detailed tracebacks and an interactive Python console on errors.
# Never use in production!
DEBUG = False

# Address for development server to listen on
HOST = "127.0.0.1"
# Port for development server to listen on
PORT = 5000

# Amount of time after which servers are removed from the list if they haven't
# updated their listings.  Note: By default Minetest servers only announce
# once every 5 minutes, so this should be more than that.
UPDATE_TIME = timedelta(minutes=6)

# Amount of time after which servers are removed from the database if they
# haven't updated their listings.
PURGE_TIME = timedelta(days=30)

# Creates server entries if a server sends an 'update' and there is no entry yet.
# This should only be used to populate the server list after list.json was deleted.
# This WILL cause problems such as mapgen, mods and privilege information missing from the list
ALLOW_UPDATE_WITHOUT_OLD = False

# Number of days' data to factor into popularity calculation
POP_DAYS = 3

# Address of the MongoDB server.  You can use domain sockets on unix.
MONGO_URI = "mongodb://localhost/minetest-master"

