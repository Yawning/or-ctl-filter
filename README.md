### or-ctl-filter - "control-port-filter" without the bash.
#### Yawning Angel (yawning at schwanenlied dot me)

or-ctl-filter is a Tor Control Port filter in the spirit of
["control-port-filter"](https://github.com/Whonix/control-port-filter) by the
Whonix developers.  It is more limited as the only use case considered is
"I want to run Tor Browser on my desktop with a system tor service and have
'about:tor' and 'New Identity' work while disallowing scary control port
commands".  But on a positive note, it's not a collection of bash and doesn't
call netcat (Yes, I'm aware that they rewrote it in Python).

Limitations/differences:
 * It is currently hardcoded to connect to a ControlSocket.
 * It only supports NULL and SAFECOOKIE authentication.
 * It does not lie about the SocksPort.
 * It does not limit request lengths, because that's tor's problem, not mine.
 * It does not allow GETINFO inquries regarding tor's bootstrap process.

Commands allowed:
 * "GETINFO net/listeners/socks"
 * "SIGNAL NEWNYM"

Example torrc:
```
# This requires the control port and cookie auth.
CookieAuthentication 1
CookieAuthFile /var/run/tor/control_auth_cookie
CookieAuthFileGroupReadable 1

# This requirs control port interaction over AF_UNIX.
ControlSocket /var/run/tor/control
ControlSocketsGroupWritable 1
```

How to run:
```
$ or-ctl-filter &
$ export TOR_SKIP_LAUNCH=1
$ export TOR_SOCKS_PORT=9050
$ start-tor-browser
```

I personally call `or-ctl-filter` from my openbox autostart file.  Bad things
will happen if multiple instances are ran at the same time since the control
port is hardcoded to what Tor Browser expects.

Bugs:
 * I should stop being lazy and add command line options so people can specify a
   password/the address of the real control port.

Acknowledgements:
 * https://www.whonix.org/wiki/Dev/Control_Port_Filter_Proxy
