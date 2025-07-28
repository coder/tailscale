// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package netns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

func control(logf logger.Logf, netMon *netmon.Monitor) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlLogf(logf, netMon, network, address, c)
	}
}

var bindToInterfaceByRouteEnv = envknob.RegisterBool("TS_BIND_TO_INTERFACE_BY_ROUTE")

var errInterfaceStateInvalid = errors.New("interface state invalid")

// routeCache caches the results of interfaceIndexFor calls to avoid
// spamming the AF_ROUTE socket. This is used for soft
// isolation mode where we do many route lookups.
var (
	routeCache     *expirable.LRU[string, int]
	routeCacheOnce sync.Once
)

func getRouteCache() *expirable.LRU[string, int] {
	routeCacheOnce.Do(func() {
		routeCache = expirable.NewLRU[string, int](256, nil, 15*time.Second)
	})
	return routeCache
}

// ClearRouteCache clears the route cache. This should be called by the
// network monitor when a link changes occur.
func ClearRouteCache() {
	// The route cache is only used in Coder soft isolation mode.
	if coderSoftIsolation.Load() {
		getRouteCache().Purge()
	}
}

// isInterfaceCoderInterface can be swapped out in tests.
var isInterfaceCoderInterface func(int) bool = isInterfaceCoderInterfaceDefault

func isInterfaceCoderInterfaceDefault(idx int) bool {
	_, tsif, err := interfaces.Coder()
	return err == nil && tsif != nil && tsif.Index == idx
}

// controlLogf binds c to the default interface if it would otherwise
// be bound to the Coder interface.
func controlLogf(logf logger.Logf, netMon *netmon.Monitor, network, address string, c syscall.RawConn) error {
	if !shouldBindToDefaultInterface(logf, netMon, address) {
		return nil
	}

	idx, err := getDefaultInterfaceIndex(logf, netMon)
	if err != nil {
		return nil
	}

	return bindConnToInterface(c, network, address, idx, logf)
}

// parseAddrForRouting returns the IP address for the given address, or an invalid
// address if the address is not specified.
func parseAddrForRouting(address string) (netip.Addr, error) {
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
		// We're not supporting addresses with zones right now.
		return netip.Addr{}, fmt.Errorf("invalid address %q, has zone: %q", address, addr.Zone())
	}

	return addr, nil
}

func shouldBindToDefaultInterface(logf logger.Logf, _ *netmon.Monitor, address string) bool {
	if isLocalhost(address) {
		// Don't bind to an interface for localhost connections.
		return false
	}

	if coderSoftIsolation.Load() {
		addr, err := parseAddrForRouting(address)
		if err != nil {
			logf("[unexpected] netns: Coder soft isolation: error parsing address %q, binding to default: %v", address, err)
			return true
		}
		if !addr.IsValid() || addr.IsUnspecified() {
			// Unspecified addresses should not be bound to any interface.
			return false
		}

		// Shortcut if the addr is a Coder IP, which we should always bind to
		// the default interface.
		if tsaddr.IsCoderIP(addr) {
			return true
		}

		// Ask Darwin routing table to find the best interface for this address
		// by using cached route lookups to avoid spamming the AF_ROUTE socket.
		idx, err := getBestInterfaceCached(addr)
		if err != nil {
			logf("[unexpected] netns: Coder soft isolation: error getting best interface, binding to default: %v", err)
			return true
		}

		if isInterfaceCoderInterface(idx) {
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

func getDefaultInterfaceIndex(logf logger.Logf, netMon *netmon.Monitor) (int, error) {
	if netMon == nil {
		idx, err := interfaces.DefaultRouteInterfaceIndex()
		if err != nil {
			// It's somewhat common for there to be no default gateway route
			// (e.g. on a phone with no connectivity), don't log those errors
			// since they are expected.
			if !errors.Is(err, interfaces.ErrNoGatewayIndexFound) {
				logf("[unexpected] netns: DefaultRouteInterfaceIndex: %v", err)
			}
			return -1, err
		}
		return idx, nil
	}

	state := netMon.InterfaceState()
	if state == nil {
		return -1, errInterfaceStateInvalid
	}

	if iface, ok := state.Interface[state.DefaultRouteInterface]; ok {
		return iface.Index, nil
	}
	return -1, errInterfaceStateInvalid
}

func getInterfaceIndex(logf logger.Logf, netMon *netmon.Monitor, address string) (int, error) {
	useRoute := bindToInterfaceByRoute.Load() || bindToInterfaceByRouteEnv()
	if !useRoute {
		return getDefaultInterfaceIndex(logf, netMon)
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port number; use the string directly.
		host = address
	}

	// If the address doesn't parse, use the default index.
	addr, err := netip.ParseAddr(host)
	if err != nil {
		logf("[unexpected] netns: error parsing address %q: %v", host, err)
		return getDefaultInterfaceIndex(logf, netMon)
	}

	idx, err := interfaceIndexFor(addr, true /* canRecurse */)
	if err != nil {
		logf("netns: error in interfaceIndexFor: %v", err)
		return getDefaultInterfaceIndex(logf, netMon)
	}

	// Verify that we didn't just choose the Coder interface;
	// if so, we fall back to binding from the default.
	_, tsif, err2 := interfaces.Coder()
	if err2 == nil && tsif != nil && tsif.Index == idx {
		logf("[unexpected] netns: interfaceIndexFor returned Coder interface")
		return getDefaultInterfaceIndex(logf, netMon)
	}

	return idx, err
}

// interfaceIndexFor returns the interface index that we should bind to in
// order to send traffic to the provided address.
func interfaceIndexFor(addr netip.Addr, canRecurse bool) (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return 0, fmt.Errorf("creating AF_ROUTE socket: %w", err)
	}
	defer unix.Close(fd)

	var routeAddr route.Addr
	if addr.Is4() {
		routeAddr = &route.Inet4Addr{IP: addr.As4()}
	} else {
		routeAddr = &route.Inet6Addr{IP: addr.As16()}
	}

	rm := route.RouteMessage{
		// NOTE: This is unix.RTM_VERSION, but we want to pin this to a
		// particular constant so that it doesn't change under us if
		// the x/sys/unix package changes down the road. Currently this
		// is 0x5 on both Darwin x86 and ARM64.
		Version: 0x5,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP,
		ID:      uintptr(os.Getpid()),
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST: routeAddr,
		},
	}
	b, err := rm.Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshaling RouteMessage: %w", err)
	}
	_, err = unix.Write(fd, b)
	if err != nil {
		return 0, fmt.Errorf("writing message: %w", err)
	}

	// On macOS, the RTM_GET call should return exactly one route message.
	// Given the following sizes and constants:
	//    - sizeof(struct rt_msghdr) = 92
	//    - RTAX_MAX = 8
	//    - sizeof(struct sockaddr_in6) = 28
	//    - sizeof(struct sockaddr_in) = 16
	//    - sizeof(struct sockaddr_dl) = 20
	//
	// The maximum buffer size should be:
	//    sizeof(struct rt_msghdr) + RTAX_MAX*sizeof(struct sockaddr_in6)
	//    = 92 + 8*28
	//    = 316
	//
	// During my testing, responses are typically ~120 bytes.
	//
	// We provide a much larger buffer just in case we're off by a bit, or
	// the kernel decides to return more than one message; 2048 bytes
	// should be plenty here. This also means we can do a single Read.
	var buf [2048]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return 0, fmt.Errorf("reading message: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
	if err != nil {
		return 0, fmt.Errorf("route.ParseRIB: %w", err)
	}
	if len(msgs) == 0 {
		return 0, fmt.Errorf("no messages")
	}

	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.Version < 3 || rm.Version > 5 || rm.Type != unix.RTM_GET {
			continue
		}
		if len(rm.Addrs) < unix.RTAX_GATEWAY {
			continue
		}

		switch addr := rm.Addrs[unix.RTAX_GATEWAY].(type) {
		case *route.LinkAddr:
			return addr.Index, nil
		case *route.Inet4Addr:
			// We can get a gateway IP; recursively call ourselves
			// (exactly once) to get the link (and thus index) for
			// the gateway IP.
			if canRecurse {
				return interfaceIndexFor(netip.AddrFrom4(addr.IP), false)
			}
		case *route.Inet6Addr:
			// As above.
			if canRecurse {
				return interfaceIndexFor(netip.AddrFrom16(addr.IP), false)
			}
		default:
			// Unknown type; skip it
			continue
		}
	}

	return 0, fmt.Errorf("no valid address found")
}

// getBestInterfaceCached returns the interface index that we should bind to in
// order to send traffic to the provided address, using a cache to avoid
// spamming the AF_ROUTE socket.
func getBestInterfaceCached(addr netip.Addr) (int, error) {
	cache := getRouteCache()
	key := addr.String()

	// Check cache first
	if idx, ok := cache.Get(key); ok {
		return idx, nil
	}

	// Cache miss, do the actual lookup
	idx, err := interfaceIndexFor(addr, true /* canRecurse */)
	if err != nil {
		// Don't cache errors
		return idx, err
	}

	// Cache only successful results
	cache.Add(key, idx)

	return idx, nil
}

// SetListenConfigInterfaceIndex sets lc.Control such that sockets are bound
// to the provided interface index.
func SetListenConfigInterfaceIndex(lc *net.ListenConfig, ifIndex int) error {
	if lc == nil {
		return errors.New("nil ListenConfig")
	}
	if lc.Control != nil {
		return errors.New("ListenConfig.Control already set")
	}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		return bindConnToInterface(c, network, address, ifIndex, log.Printf)
	}
	return nil
}

func bindConnToInterface(c syscall.RawConn, network, address string, ifIndex int, logf logger.Logf) error {
	v6 := strings.Contains(address, "]:") || strings.HasSuffix(network, "6") // hacky test for v6
	proto := unix.IPPROTO_IP
	opt := unix.IP_BOUND_IF
	if v6 {
		proto = unix.IPPROTO_IPV6
		opt = unix.IPV6_BOUND_IF
	}

	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), proto, opt, ifIndex)
	})
	if sockErr != nil {
		logf("[unexpected] netns: bindConnToInterface(%q, %q), v6=%v, index=%v: %v", network, address, v6, ifIndex, sockErr)
	}
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}
