// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netns contains the common code for using the Go net package
// in a logical "network namespace" to avoid routing loops where
// Tailscale-created packets would otherwise loop back through
// Tailscale routes.
//
// Despite the name netns, the exact mechanism used differs by
// operating system, and perhaps even by version of the OS.
//
// The netns package also handles connecting via SOCKS proxies when
// configured by the environment.
package netns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"tailscale.com/net/netknob"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

var disabled atomic.Bool

// SetEnabled enables or disables netns for the process.
// It defaults to being enabled.
func SetEnabled(on bool) {
	disabled.Store(!on)
}

var bindToInterfaceByRoute atomic.Bool

// SetBindToInterfaceByRoute enables or disables whether we use the system's
// route information to bind to a particular interface. It is the same as
// setting the TS_BIND_TO_INTERFACE_BY_ROUTE.
//
// Currently, this only changes the behaviour on macOS.
func SetBindToInterfaceByRoute(v bool) {
	bindToInterfaceByRoute.Store(v)
}

var disableBindConnToInterface atomic.Bool

// SetDisableBindConnToInterface disables the (normal) behavior of binding
// connections to the default network interface.
//
// Currently, this only has an effect on Darwin.
func SetDisableBindConnToInterface(v bool) {
	disableBindConnToInterface.Store(v)
}

var coderSoftIsolation atomic.Bool

// SetCoderSoftIsolation enables or disables Coder's soft-isolation
// functionality. All other network isolation settings are ignored when this is
// set.
//
// Soft isolation is a workaround for allowing Coder Connect to function with
// corporate VPNs. Without this, Coder Connect cannot connect to Coder
// deployments behind corporate VPNs.
//
// Soft isolation does the following:
//  1. Determine the interface that will be used for a given destination IP by
//     consulting the OS.
//  2. If that interface looks like our own, we will bind the socket to the
//     default interface (to match the existing behavior).
//  3. If it doesn't look like our own, we will let the packet flow through
//     without binding the socket to the interface.
//
// This is considered "soft" because it doesn't force the socket to be bound to
// a single interface, which causes problems with direct connections in
// magicsock.
//
// Enabling this has the risk of potential network loops, as sockets could race
// changes to the OS routing table or interface list. Coder doesn't provide
// functionality similar to Tailscale's Exit Nodes, so we don't expect loops
// to occur in our use case.
//
// This currently only has an effect on Windows and macOS, and is only used by
// Coder Connect.
func SetCoderSoftIsolation(v bool) {
	coderSoftIsolation.Store(v)
}

// Listener returns a new net.Listener with its Control hook func
// initialized as necessary to run in logical network namespace that
// doesn't route back into Tailscale.
// The netMon parameter is optional; if non-nil it's used to do faster interface lookups.
func Listener(logf logger.Logf, netMon *netmon.Monitor) *net.ListenConfig {
	if disabled.Load() {
		return new(net.ListenConfig)
	}
	return &net.ListenConfig{Control: control(logf, netMon)}
}

// NewDialer returns a new Dialer using a net.Dialer with its Control
// hook func initialized as necessary to run in a logical network
// namespace that doesn't route back into Tailscale. It also handles
// using a SOCKS if configured in the environment with ALL_PROXY.
// The netMon parameter is optional; if non-nil it's used to do faster interface lookups.
func NewDialer(logf logger.Logf, netMon *netmon.Monitor) Dialer {
	return FromDialer(logf, netMon, &net.Dialer{
		KeepAlive: netknob.PlatformTCPKeepAlive(),
	})
}

// FromDialer returns sets d.Control as necessary to run in a logical
// network namespace that doesn't route back into Tailscale. It also
// handles using a SOCKS if configured in the environment with
// ALL_PROXY.
// The netMon parameter is optional; if non-nil it's used to do faster interface lookups.
func FromDialer(logf logger.Logf, netMon *netmon.Monitor, d *net.Dialer) Dialer {
	if disabled.Load() {
		return d
	}
	d.Control = control(logf, netMon)
	if wrapDialer != nil {
		return wrapDialer(d)
	}
	return d
}

// IsSOCKSDialer reports whether d is SOCKS-proxying dialer as returned by
// NewDialer or FromDialer.
func IsSOCKSDialer(d Dialer) bool {
	if d == nil {
		return false
	}
	_, ok := d.(*net.Dialer)
	return !ok
}

// wrapDialer, if non-nil, specifies a function to wrap a dialer in a
// SOCKS-using dialer. It's set conditionally by socks.go.
var wrapDialer func(Dialer) Dialer

// Dialer is the interface for a dialer that can dial with or without a context.
// It's the type implemented both by net.Dialer and the Go SOCKS dialer.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// error means the string didn't contain a port number, so use the string directly
		host = addr
	}

	// localhost6 == RedHat /etc/hosts for ::1, ip6-loopback & ip6-localhost == Debian /etc/hosts for ::1
	if host == "localhost" || host == "localhost6" || host == "ip6-loopback" || host == "ip6-localhost" {
		return true
	}

	ip, _ := netip.ParseAddr(host)
	return ip.IsLoopback()
}

// shouldBindToDefaultInterface determines whether a socket should be bound to
// the default interface based on the destination address and soft isolation settings.
func shouldBindToDefaultInterface(logf logger.Logf, address string) bool {
	if isLocalhost(address) {
		// Don't bind to an interface for localhost connections.
		return false
	}

	if coderSoftIsolation.Load() {
		addr, err := getAddr(address)
		if err != nil {
			logf("[unexpected] netns: Coder soft isolation: error getting addr for %q, binding to default: %v", address, err)
			return true
		}
		if !addr.IsValid() || addr.IsUnspecified() {
			// Invalid or unspecified addresses should not be bound to any
			// interface.
			return false
		}
		if tsaddr.IsCoderIP(addr) {
			logf("[unexpected] netns: Coder soft isolation: detected socket destined for Coder interface, binding to default")
			return true
		}

		// It doesn't look like our own interface, so we don't need to bind the
		// socket to the default interface.
		return false
	}

	// The default isolation behavior is to always bind to the default
	// interface.
	return true
}

// getAddr returns the netip.Addr for the given address, or an invalid address
// if the address is not specified. Use addr.IsValid() to check for this.
func getAddr(address string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if host == "" {
		// netip.ParseAddr("") will fail
		return netip.Addr{}, nil
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if addr.Zone() != "" {
		// Addresses with zones *can* be represented as a Sockaddr with extra
		// effort, but we don't use or support them currently.
		return netip.Addr{}, fmt.Errorf("invalid address %q, has zone: %w", address, err)
	}
	if addr.IsUnspecified() {
		// This covers the cases of 0.0.0.0 and [::].
		return netip.Addr{}, nil
	}

	return addr, nil
}
