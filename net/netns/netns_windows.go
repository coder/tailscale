// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/cpu"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func interfaceIndex(iface *winipcfg.IPAdapterAddresses) uint32 {
	if iface == nil {
		// The zero ifidx means "unspecified". If we end up passing zero
		// to bindSocket*(), it unsets the binding and lets the socket
		// behave as normal again, which is what we want if there's no
		// default route we can use.
		return 0
	}
	return iface.IfIndex
}

// getBestInterface can be swapped out in tests.
var getBestInterface func(addr windows.Sockaddr, idx *uint32) error = windows.GetBestInterfaceEx

// isInterfaceCoderInterface can be swapped out in tests.
var isInterfaceCoderInterface func(int) bool = isInterfaceCoderInterfaceDefault

func isInterfaceCoderInterfaceDefault(idx int) bool {
	_, tsif, err := interfaces.Coder()
	return err == nil && tsif != nil && tsif.Index == idx
}

func control(logf logger.Logf, netMon *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlLogf(logf, netMon, network, address, c)
	}
}

// controlC binds c to the Windows interface that holds a default
// route, and is not the Tailscale WinTun interface.
func controlLogf(logf logger.Logf, _ *netmon.Monitor, network, address string, c syscall.RawConn) error {
	if !shouldBindToDefaultInterface(logf, address) {
		return nil
	}

	canV4, canV6 := false, false
	switch network {
	case "tcp", "udp":
		canV4, canV6 = true, true
	case "tcp4", "udp4":
		canV4 = true
	case "tcp6", "udp6":
		canV6 = true
	}

	if canV4 {
		iface, err := interfaces.GetWindowsDefault(windows.AF_INET)
		if err != nil {
			return err
		}
		if err := bindSocket4(c, interfaceIndex(iface)); err != nil {
			return err
		}
	}

	if canV6 {
		iface, err := interfaces.GetWindowsDefault(windows.AF_INET6)
		if err != nil {
			return err
		}
		if err := bindSocket6(c, interfaceIndex(iface)); err != nil {
			return err
		}
	}

	return nil
}

func shouldBindToDefaultInterface(logf logger.Logf, address string) bool {
	if strings.HasPrefix(address, "127.") {
		// Don't bind to an interface for localhost connections,
		// otherwise we get:
		//   connectex: The requested address is not valid in its context
		// (The derphttp tests were failing)
		return false
	}

	if coderSoftIsolation.Load() {
		sockAddr, err := getSockAddr(address)
		if err != nil {
			logf("[unexpected] netns: Coder soft isolation: error getting sockaddr for %q, binding to default: %v", address, err)
			return true
		}
		if sockAddr == nil {
			// Unspecified addresses should not be bound to any interface.
			return false
		}

		// Ask Windows to find the best interface for this address by consulting
		// the routing table.
		//
		// On macOS this value gets cached, but on Windows we don't need to
		// because this API is very fast and doesn't require opening an AF_ROUTE
		// socket.
		var idx uint32
		err = getBestInterface(sockAddr, &idx)
		if err != nil {
			logf("[unexpected] netns: Coder soft isolation: error getting best interface, binding to default: %v", err)
			return true
		}

		if isInterfaceCoderInterface(int(idx)) {
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

// sockoptBoundInterface is the value of IP_UNICAST_IF and IPV6_UNICAST_IF.
//
// See https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
// and https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
const sockoptBoundInterface = 31

// bindSocket4 binds the given RawConn to the network interface with
// index ifidx, for IPv4 traffic only.
func bindSocket4(c syscall.RawConn, ifidx uint32) error {
	// For IPv4 (but NOT IPv6) the interface index must be passed
	// as a big-endian integer (regardless of platform endianness)
	// because the underlying sockopt takes either an IPv4 address
	// or an index shoved into IPv4 address representation (an IP
	// in 0.0.0.0/8 means it's actually an index).
	//
	// See https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	// and IP_UNICAST_IF.
	indexAsAddr := nativeToBigEndian(ifidx)
	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, sockoptBoundInterface, int(indexAsAddr))
	})
	if err != nil {
		return err
	}
	return controlErr
}

// bindSocket6 binds the given RawConn to the network interface with
// index ifidx, for IPv6 traffic only.
func bindSocket6(c syscall.RawConn, ifidx uint32) error {
	var controlErr error
	err := c.Control(func(fd uintptr) {
		controlErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, sockoptBoundInterface, int(ifidx))
	})
	if err != nil {
		return err
	}
	return controlErr
}

// nativeToBigEndian returns i converted into big-endian
// representation, suitable for passing to Windows APIs that require a
// mangled uint32.
func nativeToBigEndian(i uint32) uint32 {
	if cpu.IsBigEndian {
		return i
	}
	return bits.ReverseBytes32(i)
}

// getSockAddr returns the Windows sockaddr for the given address, or nil if
// the address is not specified.
func getSockAddr(address string) (windows.Sockaddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if host == "" {
		// netip.ParseAddr("") will fail
		return nil, nil
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	if addr.Zone() != "" {
		// Addresses with zones *can* be represented as a Sockaddr with extra
		// effort, but we don't use or support them currently.
		return nil, fmt.Errorf("invalid address %q, has zone: %w", address, err)
	}
	if addr.IsUnspecified() {
		// This covers the cases of 0.0.0.0 and [::].
		return nil, nil
	}

	portInt, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", port, err)
	}

	if addr.Is4() {
		return &windows.SockaddrInet4{
			Port: int(portInt), // nolint:gosec // portInt is always in range
			Addr: addr.As4(),
		}, nil
	} else if addr.Is6() {
		return &windows.SockaddrInet6{
			Port: int(portInt), // nolint:gosec // portInt is always in range
			Addr: addr.As16(),
		}, nil
	}
	return nil, fmt.Errorf("invalid address %q, is not IPv4 or IPv6: %w", address, err)
}
