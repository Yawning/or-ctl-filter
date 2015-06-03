/*
 * main.go - or-ctl-filter
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// or-ctl-filter is a Tor Control Port filter/shim.  It used to be a bash-less
// rewrite of "control-port-filter" by the Whonix developers, but they have
// since rewrote "control-port-filter" in Python, and or-ctl-filter has been
// extended to provide much more functionality.
package main

import (
	"flag"
	"log"
	"sync"

	"github.com/yawning/or-ctl-filter/config"
	"github.com/yawning/or-ctl-filter/proxy"
	"github.com/yawning/or-ctl-filter/tor"
)

const defaultConfigFile = "or-ctl-filter.toml"

func main() {
	cfgFile := flag.String("config", defaultConfigFile, "config file")
	flag.Parse()

	cfg, err := config.Load(*cfgFile)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Initialize the various listeners.
	var wg sync.WaitGroup
	tor.InitCtlListener(cfg, &wg)
	proxy.InitSocksListener(cfg, &wg)

	wg.Wait()
}
