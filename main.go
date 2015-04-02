/*
 * main.go - or-ctl-filter
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// or-ctl-filter is a Tor Control Port filter in the spirit of
// "control-port-filter" by the Whonix developers.  It is more limited as the
// only use case considered is "I want to run Tor Browser on my desktop with a
// system tor service and have 'about:tor' and 'New Identity' work while
// disallowing scary control port commands".  But on a positive note, it's not
// a collection of bash and doesn't call netcat.
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
)

const (
	defaultLogFile = "or-ctl-filter.log"
	torControlAddr = "127.0.0.1:9151" // Match ControlPort in torrc-defaults.
)

func main() {
	enableLogging := flag.Bool("enable-logging", false, "enable logging")
	logFile := flag.String("log-file", defaultLogFile, "log file")
	flag.Parse()

	// Deal with logging.
	if !*enableLogging {
		log.SetOutput(ioutil.Discard)
	} else if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("Failed to create log file: %s\n", err)
		}
		log.SetOutput(f)
	}

	// Initialize the listener
	// TODO: Allow specifying where to listen on.
	ln, err := net.Listen("tcp", torControlAddr)
	if err != nil {
		log.Fatalf("Failed to listen on the filter port: %s\n", err)
	}
	defer ln.Close()

	// Listen for incoming connections, and dispatch workers.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to Accept(): %s\n", err)
			continue
		}
		s := newSession(conn)
		go s.FilterSession()
	}
}
