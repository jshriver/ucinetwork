<div align="center">
ucinetwork
</div>
<hr>

# Build instructions:
```
git clone https://github.com/jshriver/ucinetwork.git
cd ucinetwork
cargo build --release
```

# Server usage

Copy both the server.json and target/release/uciserver into a directory of your choosing. Make sure to edit the server.json so 
that the engine path and executable are correct. 

server.json
```
{
    "engine": "./stockfish",
    "bind_address": "0.0.0.0:6242"
}
```

Then execute uciserver, output example is below.

```
Detecting external IP address...
External IP: xx.xxx.xxx.xxx
Server listening on 0.0.0.0:6242
Clients should connect to: <external_ip>:6242
Waiting for connections...
```

This will work over a LAN or the internet provided you open any firewall restrictions to port 6242.

# Client usage

Copy both the client.json and target/release/uciclient into a directory of your choosing. Edit the client.json to reflect the ip address
of your serving machine.

client.json

```
{
    "server_address": "10.0.1.220:6242",
    "logfile": "client.log",
    "enable_logging": false
}
```

In your Chess GUI follow your normal procedure for adding a new engine, in this case use uciclient. 

Note: By default logging is disabled.  If you want raw logs much like my [ucitap](https://www.github.com/jshriver/ucitap) project change 
enable_logging to true.

