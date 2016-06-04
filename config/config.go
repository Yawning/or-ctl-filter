/*
 * config.go - or-ctl-filter config handler.
 *
 * To the extent possible under law, Yawning Angel has waived all copyright and
 * related or neighboring rights to or-ctl-filter, using the creative commons
 * "cc0" public domain dedication. See LICENSE or
 * <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 */

// Package config manages the or-ctl-config config file and command line
// options.
package config

import (
	"fmt"
	"io/ioutil"
	"log"
	gonet "net"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/yawning/bulb/utils"
)

// LoggingCfg stores the logging configuration parameters.
type LoggingCfg struct {
	Enable bool
	File   string
}

// TorCfg stores the Tor configuration parameters.
type TorCfg struct {
	Enable         bool
	ControlAddress string
	SOCKSAddress   string
	SuppressNewnym bool

	ctrlNet, ctrlAddr   string
	socksNet, socksAddr string
}

// I2PCfg stores the I2P configuration parameters.
type I2PCfg struct {
	Enable            bool
	EnableManagement  bool
	EnableLocal       bool
	ManagementAddress string
	LocalAddress      string
	HTTPAddress       string
	HTTPSAddress      string

	mgmtNet, mgmtAddr   string
	localNet, localAddr string
	httpNet, httpAddr   string
	httpsNet, httpsAddr string
}

// Config stores the configuration of an or-ctl-filter instance.
type Config struct {
	FilteredAddress   string
	SOCKSAddress      string
	UnsafeAllowDirect bool

	Logging LoggingCfg
	Tor     TorCfg
	I2P     I2PCfg

	fNet, fAddr         string
	socksNet, socksAddr string
}

// Load loads a TOML format or-ctl-filter configuration from a file.
func Load(path string) (*Config, error) {
	cfg := new(Config)

	if path == "" {
		log.Fatalf("No config file provided.")
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("Failed to parse config file: %v", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// FilteredNetAddr returns the networ and address of the filtered/stub control
// port.
func (cfg *Config) FilteredNetAddr() (net, addr string) {
	return cfg.fNet, cfg.fAddr
}

// SOCKSNetAddr returns the network and address of the SOCKS server.
func (cfg *Config) SOCKSNetAddr() (net, addr string) {
	return cfg.socksNet, cfg.socksAddr
}

func (cfg *Config) validate() (err error) {
	// Logging is validated/initialized first so that errors can be reported.
	if err = cfg.validateLogCfgAndInit(); err != nil {
		return err
	}

	if cfg.fNet, cfg.fAddr, err = utils.ParseControlPortString(cfg.FilteredAddress); err != nil {
		return fmt.Errorf("Failed to parse Filtered Control Port Address: %v", err)
	}
	if cfg.socksNet, cfg.socksAddr, err = parseURIAddress(cfg.SOCKSAddress); err != nil {
		return fmt.Errorf("Failed to parse Socks Address: %v", err)
	} else if cfg.socksNet != "tcp" {
		return fmt.Errorf("Socks Address must be a TCP address")
	}
	if !cfg.UnsafeAllowDirect && !cfg.Tor.Enable && !cfg.I2P.Enable {
		return fmt.Errorf("No upstream connection methods configured")
	}

	if err = cfg.Tor.validate(); err != nil {
		return err
	}
	if err = cfg.I2P.validate(); err != nil {
		return err
	}

	return nil
}

func (cfg *Config) validateLogCfgAndInit() error {
	if !cfg.Logging.Enable {
		log.SetOutput(ioutil.Discard)
		return nil
	}

	// Allow logging to the console.
	if cfg.Logging.File == "" {
		return nil
	}

	f, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("Failed to create log file: %v", err)
	}
	log.SetOutput(f)

	return nil
}

func (tCfg *TorCfg) validate() (err error) {
	if !tCfg.Enable {
		return nil
	}

	if tCfg.ctrlNet, tCfg.ctrlAddr, err = utils.ParseControlPortString(tCfg.ControlAddress); err != nil {
		return fmt.Errorf("Failed to parse Tor Control Port Address: %v", err)
	}
	if tCfg.socksNet, tCfg.socksAddr, err = parseURIAddress(tCfg.SOCKSAddress); err != nil {
		return fmt.Errorf("Failed to parse Tor SOCKS Address: %v", err)
	}

	return
}

// ControlNetAddr returns the network and address of the Tor ControlPort.
func (tCfg *TorCfg) ControlNetAddr() (net, addr string) {
	if tCfg.Enable {
		return tCfg.ctrlNet, tCfg.ctrlAddr
	}
	panic("BUG: cfg.Tor.ControlNetAddr() called when Tor is disabled.")
}

// SOCKSNetAddr returns the network and address of the Tor SOCKSPort.
func (tCfg *TorCfg) SOCKSNetAddr() (net, addr string) {
	if tCfg.Enable {
		return tCfg.socksNet, tCfg.socksAddr
	}
	panic("BUG: cfg.Tor.SOCKSNetAddr() called when Tor is disabled.")
}

func (iCfg *I2PCfg) validate() (err error) {
	if !iCfg.Enable {
		return nil
	}

	// Both of these are required to be set even if access is disabled so that
	// it is possible to reject requests.
	if iCfg.mgmtNet, iCfg.mgmtAddr, err = parseURIAddress(iCfg.ManagementAddress); err != nil {
		return fmt.Errorf("Failed to parse I2P Management Address: %v", err)
	}
	if iCfg.localNet, iCfg.localAddr, err = parseURIAddress(iCfg.LocalAddress); err != nil {
		return fmt.Errorf("Failed to parse I2P Local Server Address: %v", err)
	}

	if iCfg.httpNet, iCfg.httpAddr, err = parseURIAddress(iCfg.HTTPAddress); err != nil {
		return fmt.Errorf("Failed to parse I2P HTTP Address: %v", err)
	}
	if iCfg.httpsNet, iCfg.httpsAddr, err = parseURIAddress(iCfg.HTTPSAddress); err != nil {
		return fmt.Errorf("Failed to parse I2P HTTPS Address: %v", err)
	}

	return
}

// IsManagementHost returns true iff the address corresponds to the configured
// I2P management interface's host.
func (iCfg *I2PCfg) IsManagementHost(addr string) bool {
	if iCfg.Enable {
		host, _, err := gonet.SplitHostPort(iCfg.mgmtAddr)
		if err != nil {
			panic("BUG: cfg.I2P.ManagementAddress malformed: " + err.Error())
		}
		return addr == host
	}
	return false
}

// IsLocalHost returns true iff the address corresponds to the configured I2P
// local server's host.
func (iCfg *I2PCfg) IsLocalHost(addr string) bool {
	if iCfg.Enable {
		host, _, err := gonet.SplitHostPort(iCfg.localAddr)
		if err != nil {
			panic("BUG: cfg.I2P.LocalAddress malformed: " + err.Error())
		}
		return addr == host
	}
	return false
}

// IsManagementAddr returns true iff the address is equal to the configured I2P
// management interface's address.
func (iCfg *I2PCfg) IsManagementAddr(addr string) bool {
	if iCfg.Enable {
		return iCfg.mgmtAddr == addr
	}
	return false
}

// IsLocalAddr returns true iff the address is equal to the configured I2P
// local server's address.
func (iCfg *I2PCfg) IsLocalAddr(addr string) bool {
	if iCfg.Enable {
		return iCfg.localAddr == addr
	}
	return false
}

// HTTPNetAddr returns the network and address of the I2P HTTP proxy.
func (iCfg *I2PCfg) HTTPNetAddr() (net, addr string) {
	if iCfg.Enable {
		return iCfg.httpNet, iCfg.httpAddr
	}
	panic("BUG: cfg.I2P.HTTPNetAddr() called when I2P is disabled.")
}

// HTTPSNetAddr returns the network and address of the I2P HTTPS proxy.
func (iCfg *I2PCfg) HTTPSNetAddr() (net, addr string) {
	if iCfg.Enable {
		return iCfg.httpsNet, iCfg.httpsAddr
	}
	panic("BUG: cfg.I2P.HTTPSNetAddr() called when I2P is disabled.")
}

func parseURIAddress(raw string) (network, addr string, err error) {
	return utils.ParseControlPortString(raw)
}
