### or-ctl-filter - "control-port-filter" without the bash.
#### Yawning Angel (yawning at schwanenlied dot me)

or-ctl-filter is a Tor Control Port filter/shim.  It used to be a bash-less
rewrite of ["control-port-filter"](https://github.com/Whonix/control-port-filter)
by the Whonix developers, but they have since rewrote "control-port-filter" in
Python, and or-ctl-filter has been extended to provide much more functionality.

Dependencies:
 * https://github.com/BurntSushi/toml (TOML parser)
 * https://github.com/yawning/bulb (Control port library)
 * Tor (Runtime, optional)
 * I2P (Runtime, optional)

Limitations/differences:
 * It only supports NULL and SAFECOOKIE authentication.
 * It does not limit request lengths, because that's tor's problem, not mine.
 * It does not allow GETINFO inquries regarding tor's bootstrap process.
 * It supports any combination of Tor, and I2P, including "neither".

Commands allowed:
 * "GETINFO net/listeners/socks"
 * "SIGNAL NEWNYM"

Example torrc:
```
# This requires the control port and cookie auth.
CookieAuthentication 1
CookieAuthFile /var/run/tor/control_auth_cookie
CookieAuthFileGroupReadable 1

ControlSocket /var/run/tor/control
ControlSocketsGroupWritable 1
```

How to run:
```
$ or-ctl-filter -config=/path/to/or-ctl-filter.toml &
$ export TOR_SKIP_LAUNCH=1
$ start-tor-browser
```

I personally call `or-ctl-filter` from my openbox autostart file.  Bad things
will happen if multiple instances are ran at the same time, unless different
configurations are specified.

Notes:
 * Why yes, this assumes that both I2P and Tor are running as system services,
   and has no logic to launch either.
 * It should work on Windows, but it is entirely untested and won't be.
 * "New Identity" does not change the I2P path.
 * "New Tor Circuit for this Site" does not change the I2P path.
 * A few options are gigantic "Foot + Gun" items for the user.  In particular,
   logging is unsanitized and incredibly spammy, and `UnsafeAllowDirect`
   can allow for direct connections to the internet.

TODO:
 * Add support for I2P and `RESOLVE`/`RESOLVE_PTR`, so torsocks will work.
 * Add support for authenticating with a password, though that sucks and
   everyone should use cookie auth.
 * Think about I2P outproxy support (But honestly, why when Tor is available).
 * Consider allowing the Tor circuit display to work.
 * Consider allowing bootstrap related events.

Acknowledgements:
 * https://www.whonix.org/wiki/Dev/Control_Port_Filter_Proxy
