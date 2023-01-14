// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package resolvconffile parses & serializes /etc/resolv.conf-style files.
//
// It's a leaf package so both net/dns and net/dns/resolver can depend
// on it and we can unify a handful of implementations.
//
// The package is verbosely named to disambiguate it from resolvconf
// the daemon, which Tailscale also supports.
package resolvconffile

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"tailscale.com/util/dnsname"
	"tailscale.com/util/strs"
)

// Path is the canonical location of resolv.conf.
const Path = "/etc/resolv.conf"

// Config represents a resolv.conf(5) file.
type Config struct {
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netip.Addr

	// SearchDomains are the domain suffixes to use when expanding
	// single-label name queries. SearchDomains is additive to
	// whatever non-Tailscale search domains the OS has.
	SearchDomains []dnsname.FQDN
}

// Write writes c to w. It does so in one Write call.
func (c *Config) Write(w io.Writer) error {
	buf := new(bytes.Buffer)
	io.WriteString(buf, "# resolv.conf(5) file generated by tailscale\n")
	io.WriteString(buf, "# For more info, see http://tailscale.com/s/resolvconf-overwrite\n")
	io.WriteString(buf, "# DO NOT EDIT THIS FILE BY HAND -- CHANGES WILL BE OVERWRITTEN\n\n")
	for _, ns := range c.Nameservers {
		io.WriteString(buf, "nameserver ")
		io.WriteString(buf, ns.String())
		io.WriteString(buf, "\n")
	}
	if len(c.SearchDomains) > 0 {
		io.WriteString(buf, "search")
		for _, domain := range c.SearchDomains {
			io.WriteString(buf, " ")
			io.WriteString(buf, domain.WithoutTrailingDot())
		}
		io.WriteString(buf, "\n")
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// Parse parses a resolv.conf file from r.
func Parse(r io.Reader) (*Config, error) {
	config := new(Config)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line, _, _ = strings.Cut(line, "#") // remove any comments
		line = strings.TrimSpace(line)

		if s, ok := strs.CutPrefix(line, "nameserver"); ok {
			nameserver := strings.TrimSpace(s)
			if len(nameserver) == len(s) {
				return nil, fmt.Errorf("missing space after \"nameserver\" in %q", line)
			}
			ip, err := netip.ParseAddr(nameserver)
			if err != nil {
				return nil, err
			}
			config.Nameservers = append(config.Nameservers, ip)
			continue
		}

		if s, ok := strs.CutPrefix(line, "search"); ok {
			domains := strings.TrimSpace(s)
			if len(domains) == len(s) {
				// No leading space?!
				return nil, fmt.Errorf("missing space after \"search\" in %q", line)
			}
			for len(domains) > 0 {
				domain := domains
				i := strings.IndexAny(domain, " \t")
				if i != -1 {
					domain = domain[:i]
					domains = strings.TrimSpace(domains[i+1:])
				} else {
					domains = ""
				}
				fqdn, err := dnsname.ToFQDN(domain)
				if err != nil {
					return nil, fmt.Errorf("parsing search domain %q in %q: %w", domain, line, err)
				}
				config.SearchDomains = append(config.SearchDomains, fqdn)
			}
		}
	}
	return config, nil
}

// ParseFile parses the named resolv.conf file.
func ParseFile(name string) (*Config, error) {
	fi, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if n := fi.Size(); n > 10<<10 {
		return nil, fmt.Errorf("unexpectedly large %q file: %d bytes", name, n)
	}
	all, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return Parse(bytes.NewReader(all))
}
