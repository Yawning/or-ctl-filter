### or-ctl-filter - "control-port-filter" without the bash.
#### Yawning Angel (yawning at schwanenlied dot me)

or-ctl-filter is a Tor Control Port filter in the spirit of
["control-port-filter"](https://github.com/Whonix/control-port-filter) by the
Whonix developers.  It is more limited as the only use case considered is
"I want to run Tor Browser on my desktop with a system tor service and have
'about:tor' and 'New Identity' work while disallowing scary control port
commands".  But on a positive note, it's not a collection of bash and doesn't
call netcat.

Limitations/differences:
 * It only supports ControlSocket with CookieAuthentication.
 * It does not lie about the SocksPort.
 * It does not limit request lenghts, because that's tor's problem, not mine.
 * It does not allow GETINFO inquries regarding tor's bootstrap process.

Commands allowed:
 * "GETINFO net/listeners/socks"
 * "SIGNAL NEWNYM"

Acknowledgements:
 * https://www.whonix.org/wiki/Dev/Control_Port_Filter_Proxy
