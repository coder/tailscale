// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	wgconn "github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"go4.org/mem"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/disco"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/connstats"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/ping"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netlogtype"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/types/ptr"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/racebuild"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgcfg/nmcfg"
	"tailscale.com/wgengine/wglog"

	"github.com/coder/websocket"
)

func init() {
	os.Setenv("IN_TS_TEST", "1")

	// Some of these tests lose a disco pong before establishing a
	// direct connection, so instead of waiting 5 seconds in the
	// test, reduce the wait period.
	// (In particular, TestActiveDiscovery.)
	discoPingInterval = 100 * time.Millisecond
	pingTimeoutDuration = 100 * time.Millisecond
}

// WaitReady waits until the magicsock is entirely initialized and connected
// to its home DERP server. This is normally not necessary, since magicsock
// is intended to be entirely asynchronous, but it helps eliminate race
// conditions in tests. In particular, you can't expect two test magicsocks
// to be able to connect to each other through a test DERP unless they are
// both fully initialized before you try.
func (c *Conn) WaitReady(t testing.TB) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-c.derpStarted:
		return
	case <-c.connCtx.Done():
		t.Fatalf("magicsock.Conn closed while waiting for readiness")
	case <-timer.C:
		t.Fatalf("timeout waiting for readiness")
	}
}

func runDERPAndStun(t *testing.T, logf logger.Logf, l nettype.PacketListener, stunIP netip.Addr) (derpMap *tailcfg.DERPMap, cleanup func()) {
	d := derp.NewServer(key.NewNode(), logf)

	httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, l)

	m := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         "test-node.unused",
						IPv4:             "127.0.0.1",
						IPv6:             "none",
						STUNPort:         stunAddr.Port,
						DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						InsecureForTests: true,
						STUNTestIP:       stunIP.String(),
					},
				},
			},
		},
	}

	cleanup = func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
	}

	return m, cleanup
}

// magicStack is a magicsock, plus all the stuff around it that's
// necessary to send and receive packets to test e2e wireguard
// happiness.
type magicStack struct {
	privateKey key.NodePrivate
	epCh       chan []tailcfg.Endpoint // endpoint updates produced by this peer
	stats      *connstats.Statistics   // per-connection statistics
	conn       *Conn                   // the magicsock itself
	tun        *tuntest.ChannelTUN     // TUN device to send/receive packets
	tsTun      *tstun.Wrapper          // wrapped tun that implements filtering and wgengine hooks
	dev        *device.Device          // the wireguard-go Device that connects the previous things
	wgLogger   *wglog.Logger           // wireguard-go log wrapper
}

// newMagicStack builds and initializes an idle magicsock and
// friends. You need to call conn.SetNetworkMap and dev.Reconfig
// before anything interesting happens.
func newMagicStack(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap) *magicStack {
	privateKey := key.NewNode()
	return newMagicStackWithKey(t, logf, l, derpMap, privateKey)
}

func newMagicStackFunc(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap, updateConnFunc func(ms *Conn)) *magicStack {
	privateKey := key.NewNode()
	return newMagicStackWithKeyFunc(t, logf, l, derpMap, privateKey, updateConnFunc)
}

func newMagicStackWithKey(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap, privateKey key.NodePrivate) *magicStack {
	return newMagicStackWithKeyFunc(t, logf, l, derpMap, privateKey, nil)
}

func newMagicStackWithKeyFunc(t testing.TB, logf logger.Logf, l nettype.PacketListener, derpMap *tailcfg.DERPMap, privateKey key.NodePrivate, updateConnFunc func(ms *Conn)) *magicStack {
	t.Helper()

	epCh := make(chan []tailcfg.Endpoint, 100) // arbitrary
	conn, err := NewConn(Options{
		Logf:                   logf,
		TestOnlyPacketListener: l,
		EndpointsFunc: func(eps []tailcfg.Endpoint) {
			epCh <- eps
		},
	})
	if err != nil {
		t.Fatalf("constructing magicsock: %v", err)
	}
	conn.SetDERPMap(derpMap)
	if err := conn.SetPrivateKey(privateKey); err != nil {
		t.Fatalf("setting private key in magicsock: %v", err)
	}

	tun := tuntest.NewChannelTUN()
	tsTun := tstun.Wrap(logf, tun.TUN())
	tsTun.SetFilter(filter.NewAllowAllForTest(logf))

	wgLogger := wglog.NewLogger(logf)
	dev := wgcfg.NewDevice(tsTun, conn.Bind(), wgLogger.DeviceLogger)

	if updateConnFunc != nil {
		updateConnFunc(conn)
	}

	dev.Up()

	// Wait for magicsock to connect up to DERP.
	conn.WaitReady(t)

	// Wait for first endpoint update to be available
	deadline := time.Now().Add(2 * time.Second)
	for len(epCh) == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}

	return &magicStack{
		privateKey: privateKey,
		epCh:       epCh,
		conn:       conn,
		tun:        tun,
		tsTun:      tsTun,
		dev:        dev,
		wgLogger:   wgLogger,
	}
}

func (s *magicStack) Reconfig(cfg *wgcfg.Config) error {
	s.tsTun.SetWGConfig(cfg)
	s.wgLogger.SetPeers(cfg.Peers)
	return wgcfg.ReconfigDevice(s.dev, cfg, s.conn.logf)
}

func (s *magicStack) String() string {
	pub := s.Public()
	return pub.ShortString()
}

func (s *magicStack) Close() {
	s.dev.Close()
	s.conn.Close()
}

func (s *magicStack) Public() key.NodePublic {
	return s.privateKey.Public()
}

func (s *magicStack) Status() *ipnstate.Status {
	var sb ipnstate.StatusBuilder
	sb.WantPeers = true
	s.conn.UpdateStatus(&sb)
	return sb.Status()
}

// IP returns the Tailscale IP address assigned to this magicStack.
//
// Something external needs to provide a NetworkMap and WireGuard
// configs to the magicStack in order for it to acquire an IP
// address. See meshStacks for one possible source of netmaps and IPs.
func (s *magicStack) IP() netip.Addr {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		st := s.Status()
		if len(st.TailscaleIPs) > 0 {
			return st.TailscaleIPs[0]
		}
	}
	panic("timed out waiting for magicstack to get an IP assigned")
}

// meshStacks monitors epCh on all given ms, and plumbs network maps
// and WireGuard configs into everyone to form a full mesh that has up
// to date endpoint info. Think of it as an extremely stripped down
// and purpose-built Tailscale control plane.
func meshStacks(logf logger.Logf, mutateNetmap func(idx int, nm *netmap.NetworkMap), ms ...*magicStack) (cleanup func()) {
	ctx, cancel := context.WithCancel(context.Background())

	// Serialize all reconfigurations globally, just to keep things
	// simpler.
	var (
		mu  sync.Mutex
		eps = make([][]tailcfg.Endpoint, len(ms))
	)

	buildNetmapLocked := func(myIdx int) *netmap.NetworkMap {
		me := ms[myIdx]
		nm := &netmap.NetworkMap{
			PrivateKey: me.privateKey,
			NodeKey:    me.privateKey.Public(),
			Addresses:  []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(myIdx+1)), 32)},
		}
		for i, peer := range ms {
			if i == myIdx {
				continue
			}
			addrs := []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(i+1)), 32)}
			peer := &tailcfg.Node{
				ID:         tailcfg.NodeID(i + 1),
				Name:       fmt.Sprintf("node%d", i+1),
				Key:        peer.privateKey.Public(),
				DiscoKey:   peer.conn.DiscoPublicKey(),
				Addresses:  addrs,
				AllowedIPs: addrs,
				Endpoints:  epStrings(eps[i]),
				DERP:       "127.3.3.40:1",
			}
			nm.Peers = append(nm.Peers, peer)
		}

		if mutateNetmap != nil {
			mutateNetmap(myIdx, nm)
		}
		return nm
	}

	updateEps := func(idx int, newEps []tailcfg.Endpoint) {
		mu.Lock()
		defer mu.Unlock()

		eps[idx] = newEps

		for i, m := range ms {
			nm := buildNetmapLocked(i)
			m.conn.SetNetworkMap(nm)
			peerSet := make(map[key.NodePublic]struct{}, len(nm.Peers))
			for _, peer := range nm.Peers {
				peerSet[peer.Key] = struct{}{}
			}
			m.conn.UpdatePeers(peerSet)
			wg, err := nmcfg.WGCfg(nm, logf, netmap.AllowSingleHosts, "")
			if err != nil {
				// We're too far from the *testing.T to be graceful,
				// blow up. Shouldn't happen anyway.
				panic(fmt.Sprintf("failed to construct wgcfg from netmap: %v", err))
			}
			if err := m.Reconfig(wg); err != nil {
				if ctx.Err() != nil || errors.Is(err, errConnClosed) {
					// shutdown race, don't care.
					return
				}
				panic(fmt.Sprintf("device reconfig failed: %v", err))
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(ms))
	for i := range ms {
		go func(myIdx int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case eps := <-ms[myIdx].epCh:
					logf("conn%d endpoints update", myIdx+1)
					updateEps(myIdx, eps)
				}
			}
		}(i)
	}

	return func() {
		cancel()
		wg.Wait()
	}
}

func TestNewConn(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	epCh := make(chan string, 16)
	epFunc := func(endpoints []tailcfg.Endpoint) {
		for _, ep := range endpoints {
			epCh <- ep.Addr.String()
		}
	}

	stunAddr, stunCleanupFn := stuntest.Serve(t)
	defer stunCleanupFn()

	port := pickPort(t)
	conn, err := NewConn(Options{
		Port:          port,
		EndpointsFunc: epFunc,
		Logf:          t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDERPMap(stuntest.DERPMapOf(stunAddr.String()))
	conn.SetPrivateKey(key.NewNode())

	go func() {
		pkts := make([][]byte, 1)
		sizes := make([]int, 1)
		eps := make([]wgconn.Endpoint, 1)
		pkts[0] = make([]byte, 64<<10)
		receiveIPv4 := conn.receiveIPv4()
		for {
			_, err := receiveIPv4(pkts, sizes, eps)
			if err != nil {
				return
			}
		}
	}()

	timeout := time.After(10 * time.Second)
	var endpoints []string
	suffix := fmt.Sprintf(":%d", port)
collectEndpoints:
	for {
		select {
		case ep := <-epCh:
			t.Logf("TestNewConn: got endpoint: %v", ep)
			endpoints = append(endpoints, ep)
			if strings.HasSuffix(ep, suffix) {
				break collectEndpoints
			}
		case <-timeout:
			t.Fatalf("timeout with endpoints: %v", endpoints)
		}
	}
}

func pickPort(t testing.TB) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port)
}

func TestPickDERPFallback(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	c := newConn()
	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {Nodes: []*tailcfg.DERPNode{{}}},
			2: {Nodes: []*tailcfg.DERPNode{{}}},
			3: {Nodes: []*tailcfg.DERPNode{{}}},
			4: {Nodes: []*tailcfg.DERPNode{{}}},
			5: {Nodes: []*tailcfg.DERPNode{{}}},
			6: {Nodes: []*tailcfg.DERPNode{{}}},
			7: {Nodes: []*tailcfg.DERPNode{{}}},
			8: {Nodes: []*tailcfg.DERPNode{{}}},
		},
	}
	c.derpMap = dm
	a := c.pickDERPFallback()
	if a == 0 {
		t.Fatalf("pickDERPFallback returned 0")
	}

	// Test that it's consistent.
	for i := 0; i < 50; i++ {
		b := c.pickDERPFallback()
		if a != b {
			t.Fatalf("got inconsistent %d vs %d values", a, b)
		}
	}

	// Test that that the pointer value of c is blended in and
	// distribution over nodes works.
	got := map[int]int{}
	for i := 0; i < 50; i++ {
		c = newConn()
		c.derpMap = dm
		got[c.pickDERPFallback()]++
	}
	t.Logf("distribution: %v", got)
	if len(got) < 2 {
		t.Errorf("expected more than 1 node; got %v", got)
	}

	// Test that stickiness works.
	const someNode = 123456
	c.myDerp = someNode
	if got := c.pickDERPFallback(); got != someNode {
		t.Errorf("not sticky: got %v; want %v", got, someNode)
	}

	// TODO: test that disco-based clients changing to a new DERP
	// region causes this fallback to also move, once disco clients
	// have fixed DERP fallback logic.
}

// TestDeviceStartStop exercises the startup and shutdown logic of
// wireguard-go, which is intimately intertwined with magicsock's own
// lifecycle. We seem to be good at generating deadlocks here, so if
// this test fails you should suspect a deadlock somewhere in startup
// or shutdown. It may be an infrequent flake, so run with
// -count=10000 to be sure.
func TestDeviceStartStop(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	conn, err := NewConn(Options{
		EndpointsFunc: func(eps []tailcfg.Endpoint) {},
		Logf:          t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tun := tuntest.NewChannelTUN()
	wgLogger := wglog.NewLogger(t.Logf)
	dev := wgcfg.NewDevice(tun.TUN(), conn.Bind(), wgLogger.DeviceLogger)
	dev.Up()
	dev.Close()
}

// Exercise a code path in sendDiscoMessage if the connection has been closed.
func TestConnClosed(t *testing.T) {
	mstun := &natlab.Machine{Name: "stun"}
	m1 := &natlab.Machine{Name: "m1"}
	m2 := &natlab.Machine{Name: "m2"}
	inet := natlab.NewInternet()
	sif := mstun.Attach("eth0", inet)
	m1if := m1.Attach("eth0", inet)
	m2if := m2.Attach("eth0", inet)

	d := &devices{
		m1:     m1,
		m1IP:   m1if.V4(),
		m2:     m2,
		m2IP:   m2if.V4(),
		stun:   mstun,
		stunIP: sif.V4(),
	}

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	ms1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap)
	defer ms1.Close()
	ms2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap)
	defer ms2.Close()

	cleanup = meshStacks(t.Logf, nil, ms1, ms2)
	defer cleanup()

	pkt := tuntest.Ping(ms2.IP(), ms1.IP())

	if len(ms1.conn.activeDerp) == 0 {
		t.Errorf("unexpected DERP empty got: %v want: >0", len(ms1.conn.activeDerp))
	}

	ms1.conn.Close()
	ms2.conn.Close()

	// This should hit a c.closed conditional in sendDiscoMessage() and return immediately.
	ms1.tun.Outbound <- pkt
	select {
	case <-ms2.tun.Inbound:
		t.Error("unexpected response with connection closed")
	case <-time.After(100 * time.Millisecond):
	}

	if len(ms1.conn.activeDerp) > 0 {
		t.Errorf("unexpected DERP active got: %v want:0", len(ms1.conn.activeDerp))
	}
}

func makeNestable(t *testing.T) (logf logger.Logf, setT func(t *testing.T)) {
	var mu sync.RWMutex
	cur := t

	setT = func(t *testing.T) {
		mu.Lock()
		cur = t
		mu.Unlock()
	}

	logf = func(s string, args ...any) {
		mu.RLock()
		t := cur

		t.Helper()
		t.Logf(s, args...)
		mu.RUnlock()
	}

	return logf, setT
}

// localhostOnlyListener is a nettype.PacketListener that listens on
// localhost (127.0.0.1 or ::1, depending on the requested network)
// when asked to listen on the unspecified address.
//
// It's used in tests where we set up localhost-to-localhost
// communication, because if you listen on the unspecified address on
// macOS and Windows, you get an interactive firewall consent prompt
// to allow the binding, which breaks our CIs.
type localhostListener struct{}

func (localhostListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	switch network {
	case "udp4":
		switch host {
		case "", "0.0.0.0":
			host = "127.0.0.1"
		case "127.0.0.1":
		default:
			return nil, fmt.Errorf("localhostListener cannot be asked to listen on %q", address)
		}
	case "udp6":
		switch host {
		case "", "::":
			host = "::1"
		case "::1":
		default:
			return nil, fmt.Errorf("localhostListener cannot be asked to listen on %q", address)
		}
	}
	var conf net.ListenConfig
	return conf.ListenPacket(ctx, network, net.JoinHostPort(host, port))
}

func TestTwoDevicePing(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/1277")
	l, ip := localhostListener{}, netaddr.IPv4(127, 0, 0, 1)
	n := &devices{
		m1:     l,
		m1IP:   ip,
		m2:     l,
		m2IP:   ip,
		stun:   l,
		stunIP: ip,
	}
	testTwoDevicePing(t, n)
}

func TestDiscokeyChange(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m1Key := key.NewNode()
	m1 := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, m1Key)
	defer m1.Close()
	m2 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m2.Close()

	var (
		mu sync.Mutex
		// Start with some random discoKey that isn't actually m1's key,
		// to simulate m2 coming up with knowledge of an old, expired
		// discokey. We'll switch to the correct one later in the test.
		m1DiscoKey = key.NewDisco().Public()
	)
	setm1Key := func(idx int, nm *netmap.NetworkMap) {
		if idx != 1 {
			// only mutate m2's netmap
			return
		}
		if len(nm.Peers) != 1 {
			// m1 not in netmap yet.
			return
		}
		mu.Lock()
		defer mu.Unlock()
		nm.Peers[0].DiscoKey = m1DiscoKey
	}

	cleanupMesh := meshStacks(t.Logf, setm1Key, m1, m2)
	defer cleanupMesh()

	// Wait for both peers to know about each other.
	for {
		if s1 := m1.Status(); len(s1.Peer) != 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if s2 := m2.Status(); len(s2.Peer) != 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}

	mu.Lock()
	m1DiscoKey = m1.conn.DiscoPublicKey()
	mu.Unlock()

	// Manually trigger an endpoint update to meshStacks, so it hands
	// m2 a new netmap.
	m1.conn.mu.Lock()
	m1.epCh <- m1.conn.lastEndpoints
	m1.conn.mu.Unlock()

	cleanup = newPinger(t, t.Logf, m1, m2)
	defer cleanup()

	mustDirect(t, t.Logf, m1, m2)
	mustDirect(t, t.Logf, m2, m1)
}

func TestActiveDiscovery(t *testing.T) {
	t.Run("simple_internet", func(t *testing.T) {
		t.Parallel()
		mstun := &natlab.Machine{Name: "stun"}
		m1 := &natlab.Machine{Name: "m1"}
		m2 := &natlab.Machine{Name: "m2"}
		inet := natlab.NewInternet()
		sif := mstun.Attach("eth0", inet)
		m1if := m1.Attach("eth0", inet)
		m2if := m2.Attach("eth0", inet)

		n := &devices{
			m1:     m1,
			m1IP:   m1if.V4(),
			m2:     m2,
			m2IP:   m2if.V4(),
			stun:   mstun,
			stunIP: sif.V4(),
		}
		testActiveDiscovery(t, n)
	})

	t.Run("facing_easy_firewalls", func(t *testing.T) {
		mstun := &natlab.Machine{Name: "stun"}
		m1 := &natlab.Machine{
			Name:          "m1",
			PacketHandler: &natlab.Firewall{},
		}
		m2 := &natlab.Machine{
			Name:          "m2",
			PacketHandler: &natlab.Firewall{},
		}
		inet := natlab.NewInternet()
		sif := mstun.Attach("eth0", inet)
		m1if := m1.Attach("eth0", inet)
		m2if := m2.Attach("eth0", inet)

		n := &devices{
			m1:     m1,
			m1IP:   m1if.V4(),
			m2:     m2,
			m2IP:   m2if.V4(),
			stun:   mstun,
			stunIP: sif.V4(),
		}
		testActiveDiscovery(t, n)
	})

	t.Run("facing_nats", func(t *testing.T) {
		mstun := &natlab.Machine{Name: "stun"}
		m1 := &natlab.Machine{
			Name:          "m1",
			PacketHandler: &natlab.Firewall{},
		}
		nat1 := &natlab.Machine{
			Name: "nat1",
		}
		m2 := &natlab.Machine{
			Name:          "m2",
			PacketHandler: &natlab.Firewall{},
		}
		nat2 := &natlab.Machine{
			Name: "nat2",
		}

		inet := natlab.NewInternet()
		lan1 := &natlab.Network{
			Name:    "lan1",
			Prefix4: netip.MustParsePrefix("192.168.0.0/24"),
		}
		lan2 := &natlab.Network{
			Name:    "lan2",
			Prefix4: netip.MustParsePrefix("192.168.1.0/24"),
		}

		sif := mstun.Attach("eth0", inet)
		nat1WAN := nat1.Attach("wan", inet)
		nat1LAN := nat1.Attach("lan1", lan1)
		nat2WAN := nat2.Attach("wan", inet)
		nat2LAN := nat2.Attach("lan2", lan2)
		m1if := m1.Attach("eth0", lan1)
		m2if := m2.Attach("eth0", lan2)
		lan1.SetDefaultGateway(nat1LAN)
		lan2.SetDefaultGateway(nat2LAN)

		nat1.PacketHandler = &natlab.SNAT44{
			Machine:           nat1,
			ExternalInterface: nat1WAN,
			Firewall: &natlab.Firewall{
				TrustedInterface: nat1LAN,
			},
		}
		nat2.PacketHandler = &natlab.SNAT44{
			Machine:           nat2,
			ExternalInterface: nat2WAN,
			Firewall: &natlab.Firewall{
				TrustedInterface: nat2LAN,
			},
		}

		n := &devices{
			m1:     m1,
			m1IP:   m1if.V4(),
			m2:     m2,
			m2IP:   m2if.V4(),
			stun:   mstun,
			stunIP: sif.V4(),
		}
		testActiveDiscovery(t, n)
	})
}

type devices struct {
	m1   nettype.PacketListener
	m1IP netip.Addr

	m2   nettype.PacketListener
	m2IP netip.Addr

	stun   nettype.PacketListener
	stunIP netip.Addr
}

// newPinger starts continuously sending test packets from srcM to
// dstM, until cleanup is invoked to stop it. Each ping has 1 second
// to transit the network. It is a test failure to lose a ping.
func newPinger(t *testing.T, logf logger.Logf, src, dst *magicStack) (cleanup func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	one := func() bool {
		// TODO(danderson): requiring exactly zero packet loss
		// will probably be too strict for some tests we'd like to
		// run (e.g. discovery switching to a new path on
		// failure). Figure out what kind of thing would be
		// acceptable to test instead of "every ping must
		// transit".
		pkt := tuntest.Ping(dst.IP(), src.IP())
		select {
		case src.tun.Outbound <- pkt:
		case <-ctx.Done():
			return false
		}
		select {
		case <-dst.tun.Inbound:
			return true
		case <-time.After(10 * time.Second):
			// Very generous timeout here because depending on
			// magicsock setup races, the first handshake might get
			// eaten by the receiving end (if wireguard-go hasn't been
			// configured quite yet), so we have to wait for at least
			// the first retransmit from wireguard before we declare
			// failure.
			t.Errorf("timed out waiting for ping to transit")
			return true
		case <-ctx.Done():
			// Try a little bit longer to consume the packet we're
			// waiting for. This is to deal with shutdown races, where
			// natlab may still be delivering a packet to us from a
			// goroutine.
			select {
			case <-dst.tun.Inbound:
			case <-time.After(time.Second):
			}
			return false
		}
	}

	cleanup = func() {
		cancel()
		<-done
	}

	// Synchronously transit one ping to get things started. This is
	// nice because it means that newPinger returning means we've
	// worked through initial connectivity.
	if !one() {
		cleanup()
		return
	}

	go func() {
		logf("sending ping stream from %s (%s) to %s (%s)", src, src.IP(), dst, dst.IP())
		defer close(done)
		for one() {
		}
	}()

	return cleanup
}

// testActiveDiscovery verifies that two magicStacks tied to the given
// devices can establish a direct p2p connection with each other. See
// TestActiveDiscovery for the various configurations of devices that
// get exercised.
func testActiveDiscovery(t *testing.T, d *devices) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	tlogf, setT := makeNestable(t)
	setT(t)

	start := time.Now()
	wlogf := func(msg string, args ...any) {
		t.Helper()
		msg = fmt.Sprintf("%s: %s", time.Since(start).Truncate(time.Microsecond), msg)
		tlogf(msg, args...)
	}
	logf, closeLogf := logger.LogfCloser(wlogf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	m1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap)
	defer m2.Close()

	cleanup = meshStacks(logf, nil, m1, m2)
	defer cleanup()

	m1IP := m1.IP()
	m2IP := m2.IP()
	logf("IPs: %s %s", m1IP, m2IP)

	cleanup = newPinger(t, logf, m1, m2)
	defer cleanup()

	// Everything is now up and running, active discovery should find
	// a direct path between our peers. Wait for it to switch away
	// from DERP.
	mustDirect(t, logf, m1, m2)
	mustDirect(t, logf, m2, m1)

	logf("starting cleanup")
}

func mustDirect(t *testing.T, logf logger.Logf, m1, m2 *magicStack) {
	lastLog := time.Now().Add(-time.Minute)
	// See https://github.com/tailscale/tailscale/issues/654
	// and https://github.com/tailscale/tailscale/issues/3247 for discussions of this deadline.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		pst := m1.Status().Peer[m2.Public()]
		if pst.CurAddr != "" {
			logf("direct link %s->%s found with addr %s", m1, m2, pst.CurAddr)
			return
		}
		if now := time.Now(); now.Sub(lastLog) > time.Second {
			logf("no direct path %s->%s yet, addrs %v", m1, m2, pst.Addrs)
			lastLog = now
		}
	}
	t.Errorf("magicsock did not find a direct path from %s to %s", m1, m2)
}

func testTwoDevicePing(t *testing.T, d *devices) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	// This gets reassigned inside every test, so that the connections
	// all log using the "current" t.Logf function. Sigh.
	nestedLogf, setT := makeNestable(t)

	logf, closeLogf := logger.LogfCloser(nestedLogf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	m1 := newMagicStack(t, logf, d.m1, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logf, d.m2, derpMap)
	defer m2.Close()

	cleanupMesh := meshStacks(logf, nil, m1, m2)
	defer cleanupMesh()

	// Wait for magicsock to be told about peers from meshStacks.
	tstest.WaitFor(10*time.Second, func() error {
		if p := m1.Status().Peer[m2.Public()]; p == nil || !p.InMagicSock {
			return errors.New("m1 not ready")
		}
		if p := m2.Status().Peer[m1.Public()]; p == nil || !p.InMagicSock {
			return errors.New("m2 not ready")
		}
		return nil
	})

	m1cfg := &wgcfg.Config{
		Name:       "peer1",
		PrivateKey: m1.privateKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")},
		Peers: []wgcfg.Peer{
			{
				PublicKey:  m2.privateKey.Public(),
				DiscoKey:   m2.conn.DiscoPublicKey(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("1.0.0.2/32")},
			},
		},
	}
	m2cfg := &wgcfg.Config{
		Name:       "peer2",
		PrivateKey: m2.privateKey,
		Addresses:  []netip.Prefix{netip.MustParsePrefix("1.0.0.2/32")},
		Peers: []wgcfg.Peer{
			{
				PublicKey:  m1.privateKey.Public(),
				DiscoKey:   m1.conn.DiscoPublicKey(),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("1.0.0.1/32")},
			},
		},
	}

	if err := m1.Reconfig(m1cfg); err != nil {
		t.Fatal(err)
	}
	if err := m2.Reconfig(m2cfg); err != nil {
		t.Fatal(err)
	}

	// In the normal case, pings succeed immediately.
	// However, in the case of a handshake race, we need to retry.
	// With very bad luck, we can need to retry multiple times.
	allowedRetries := 3
	if cibuild.On() {
		// Allow extra retries on small/flaky/loaded CI machines.
		allowedRetries *= 2
	}
	// Retries take 5s each. Add 1s for some processing time.
	pingTimeout := 5*time.Second*time.Duration(allowedRetries) + time.Second

	// sendWithTimeout sends msg using send, checking that it is received unchanged from in.
	// It resends once per second until the send succeeds, or pingTimeout time has elapsed.
	sendWithTimeout := func(msg []byte, in chan []byte, send func()) error {
		start := time.Now()
		for time.Since(start) < pingTimeout {
			send()
			select {
			case recv := <-in:
				if !bytes.Equal(msg, recv) {
					return errors.New("ping did not transit correctly")
				}
				return nil
			case <-time.After(time.Second):
				// try again
			}
		}
		return errors.New("ping timed out")
	}

	ping1 := func(t *testing.T) {
		msg2to1 := tuntest.Ping(netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.0.0.2"))
		send := func() {
			m2.tun.Outbound <- msg2to1
			t.Log("ping1 sent")
		}
		in := m1.tun.Inbound
		if err := sendWithTimeout(msg2to1, in, send); err != nil {
			t.Error(err)
		}
	}
	ping2 := func(t *testing.T) {
		msg1to2 := tuntest.Ping(netip.MustParseAddr("1.0.0.2"), netip.MustParseAddr("1.0.0.1"))
		send := func() {
			m1.tun.Outbound <- msg1to2
			t.Log("ping2 sent")
		}
		in := m2.tun.Inbound
		if err := sendWithTimeout(msg1to2, in, send); err != nil {
			t.Error(err)
		}
	}

	m1.stats = connstats.NewStatistics(0, 0, nil)
	defer m1.stats.Shutdown(context.Background())
	m1.conn.SetStatistics(m1.stats)
	m2.stats = connstats.NewStatistics(0, 0, nil)
	defer m2.stats.Shutdown(context.Background())
	m2.conn.SetStatistics(m2.stats)

	checkStats := func(t *testing.T, m *magicStack, wantConns []netlogtype.Connection) {
		_, stats := m.stats.TestExtract()
		for _, conn := range wantConns {
			if _, ok := stats[conn]; ok {
				return
			}
		}
		t.Helper()
		t.Errorf("missing any connection to %s from %s", wantConns, maps.Keys(stats))
	}

	addrPort := netip.MustParseAddrPort
	m1Conns := []netlogtype.Connection{
		{Src: addrPort("1.0.0.2:0"), Dst: m2.conn.pconn4.LocalAddr().AddrPort()},
		{Src: addrPort("1.0.0.2:0"), Dst: addrPort("127.3.3.40:1")},
	}
	m2Conns := []netlogtype.Connection{
		{Src: addrPort("1.0.0.1:0"), Dst: m1.conn.pconn4.LocalAddr().AddrPort()},
		{Src: addrPort("1.0.0.1:0"), Dst: addrPort("127.3.3.40:1")},
	}

	outerT := t
	t.Run("ping 1.0.0.1", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		ping1(t)
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		ping2(t)
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})

	t.Run("ping 1.0.0.2 via SendPacket", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		msg1to2 := tuntest.Ping(netip.MustParseAddr("1.0.0.2"), netip.MustParseAddr("1.0.0.1"))
		send := func() {
			if err := m1.tsTun.InjectOutbound(msg1to2); err != nil {
				t.Fatal(err)
			}
			t.Log("SendPacket sent")
		}
		in := m2.tun.Inbound
		if err := sendWithTimeout(msg1to2, in, send); err != nil {
			t.Error(err)
		}
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})

	t.Run("no-op dev1 reconfig", func(t *testing.T) {
		setT(t)
		defer setT(outerT)
		if err := m1.Reconfig(m1cfg); err != nil {
			t.Fatal(err)
		}
		ping1(t)
		ping2(t)
		checkStats(t, m1, m1Conns)
		checkStats(t, m2, m2Conns)
	})
}

func TestDiscoMessage(t *testing.T) {
	c := newConn()
	c.logf = t.Logf
	c.privateKey = key.NewNode()

	peer1Pub := c.DiscoPublicKey()
	peer1Priv := c.discoPrivate
	n := &tailcfg.Node{
		Key:      key.NewNode().Public(),
		DiscoKey: peer1Pub,
	}
	ep := &endpoint{
		publicKey: n.Key,
	}
	ep.disco.Store(&endpointDisco{
		key:   n.DiscoKey,
		short: n.DiscoKey.ShortString(),
	})
	c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})

	const payload = "why hello"

	var nonce [24]byte
	crand.Read(nonce[:])

	pkt := peer1Pub.AppendTo([]byte("TS💬"))

	box := peer1Priv.Shared(c.discoPrivate.Public()).Seal([]byte(payload))
	pkt = append(pkt, box...)
	got := c.handleDiscoMessage(pkt, netip.AddrPort{}, key.NodePublic{}, discoRXPathUDP)
	if !got {
		t.Error("failed to open it")
	}
}

// tests that having a endpoint.String prevents wireguard-go's
// log.Printf("%v") of its conn.Endpoint values from using reflect to
// walk into read mutex while they're being used and then causing data
// races.
func TestDiscoStringLogRace(t *testing.T) {
	de := new(endpoint)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		fmt.Fprintf(io.Discard, "%v", de)
	}()
	go func() {
		defer wg.Done()
		de.mu.Lock()
	}()
	wg.Wait()
}

func Test32bitAlignment(t *testing.T) {
	// Need an associated conn with non-nil noteRecvActivity to
	// trigger interesting work on the atomics in endpoint.
	called := 0
	de := endpoint{
		c: &Conn{
			noteRecvActivity: func(key.NodePublic) { called++ },
		},
	}

	if off := unsafe.Offsetof(de.lastRecv); off%8 != 0 {
		t.Fatalf("endpoint.lastRecv is not 8-byte aligned")
	}

	de.noteRecvActivity() // verify this doesn't panic on 32-bit
	if called != 1 {
		t.Fatal("expected call to noteRecvActivity")
	}
	de.noteRecvActivity()
	if called != 1 {
		t.Error("expected no second call to noteRecvActivity")
	}
}

// newTestConn returns a new Conn.
func newTestConn(t testing.TB) *Conn {
	t.Helper()
	port := pickPort(t)
	conn, err := NewConn(Options{
		Logf:                   t.Logf,
		Port:                   port,
		TestOnlyPacketListener: localhostListener{},
		EndpointsFunc: func(eps []tailcfg.Endpoint) {
			t.Logf("endpoints: %q", eps)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// addTestEndpoint sets conn's network map to a single peer expected
// to receive packets from sendConn (or DERP), and returns that peer's
// nodekey and discokey.
func addTestEndpoint(tb testing.TB, conn *Conn, sendConn net.PacketConn) (key.NodePublic, key.DiscoPublic) {
	// Give conn just enough state that it'll recognize sendConn as a
	// valid peer and not fall through to the legacy magicsock
	// codepath.
	discoKey := key.DiscoPublicFromRaw32(mem.B([]byte{31: 1}))
	nodeKey := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 31: 0}))
	conn.SetNetworkMap(&netmap.NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Key:       nodeKey,
				DiscoKey:  discoKey,
				Endpoints: []string{sendConn.LocalAddr().String()},
			},
		},
	})
	conn.SetPrivateKey(key.NodePrivateFromRaw32(mem.B([]byte{0: 1, 31: 0})))
	_, err := conn.ParseEndpoint(nodeKey.UntypedHexString())
	if err != nil {
		tb.Fatal(err)
	}
	conn.addValidDiscoPathForTest(nodeKey, netip.MustParseAddrPort(sendConn.LocalAddr().String()))
	return nodeKey, discoKey
}

func setUpReceiveFrom(tb testing.TB) (roundTrip func()) {
	if b, ok := tb.(*testing.B); ok {
		b.ReportAllocs()
	}

	conn := newTestConn(tb)
	tb.Cleanup(func() { conn.Close() })
	conn.logf = logger.Discard

	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { sendConn.Close() })

	addTestEndpoint(tb, conn, sendConn)

	var dstAddr net.Addr = conn.pconn4.LocalAddr()
	sendBuf := make([]byte, 1<<10)
	for i := range sendBuf {
		sendBuf[i] = 'x'
	}
	buffs := make([][]byte, 1)
	buffs[0] = make([]byte, 2<<10)
	sizes := make([]int, 1)
	eps := make([]wgconn.Endpoint, 1)
	receiveIPv4 := conn.receiveIPv4()
	return func() {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			tb.Fatalf("WriteTo: %v", err)
		}
		n, err := receiveIPv4(buffs, sizes, eps)
		if err != nil {
			tb.Fatal(err)
		}
		_ = n
		_ = eps
	}
}

// goMajorVersion reports the major Go version and whether it is a Tailscale fork.
// If parsing fails, goMajorVersion returns 0, false.
func goMajorVersion(s string) (version int, isTS bool) {
	if !strings.HasPrefix(s, "go1.") {
		return 0, false
	}
	mm := s[len("go1."):]
	var major, rest string
	for _, sep := range []string{".", "rc", "beta", "-"} {
		i := strings.Index(mm, sep)
		if i > 0 {
			major, rest = mm[:i], mm[i:]
			break
		}
	}
	if major == "" {
		major = mm
	}
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, false
	}
	return n, strings.Contains(rest, "ts")
}

func TestGoMajorVersion(t *testing.T) {
	tests := []struct {
		version string
		wantN   int
		wantTS  bool
	}{
		{"go1.15.8", 15, false},
		{"go1.16rc1", 16, false},
		{"go1.16rc1", 16, false},
		{"go1.15.5-ts3bd89195a3", 15, true},
		{"go1.15", 15, false},
		{"go1.18-ts0d07ed810a", 18, true},
	}

	for _, tt := range tests {
		n, ts := goMajorVersion(tt.version)
		if tt.wantN != n || tt.wantTS != ts {
			t.Errorf("goMajorVersion(%s) = %v, %v, want %v, %v", tt.version, n, ts, tt.wantN, tt.wantTS)
		}
	}

	// Ensure that the current Go version is parseable.
	n, _ := goMajorVersion(runtime.Version())
	if n == 0 {
		t.Fatalf("unable to parse %v", runtime.Version())
	}
}

func TestReceiveFromAllocs(t *testing.T) {
	// TODO(jwhited): we are back to nonzero alloc due to our use of x/net until
	//  https://github.com/golang/go/issues/45886 is implemented.
	t.Skip("alloc tests are skipped until https://github.com/golang/go/issues/45886 is implemented and plumbed.")
	if racebuild.On {
		t.Skip("alloc tests are unreliable with -race")
	}
	// Go 1.16 and before: allow 3 allocs.
	// Go 1.17: allow 2 allocs.
	// Go 1.17, Tailscale fork: allow 1 alloc.
	// Go 1.18+: allow 0 allocs.
	// Go 2.0: allow -1 allocs (projected).
	major, ts := goMajorVersion(runtime.Version())
	maxAllocs := 3
	switch {
	case major == 17 && !ts:
		maxAllocs = 2
	case major == 17 && ts:
		maxAllocs = 1
	case major >= 18:
		maxAllocs = 0
	}
	t.Logf("allowing %d allocs for Go version %q", maxAllocs, runtime.Version())
	roundTrip := setUpReceiveFrom(t)
	err := tstest.MinAllocsPerRun(t, uint64(maxAllocs), roundTrip)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkReceiveFrom(b *testing.B) {
	roundTrip := setUpReceiveFrom(b)
	for i := 0; i < b.N; i++ {
		roundTrip()
	}
}

func BenchmarkReceiveFrom_Native(b *testing.B) {
	b.ReportAllocs()
	recvConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer recvConn.Close()
	recvConnUDP := recvConn.(*net.UDPConn)

	sendConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer sendConn.Close()

	var dstAddr net.Addr = recvConn.LocalAddr()
	sendBuf := make([]byte, 1<<10)
	for i := range sendBuf {
		sendBuf[i] = 'x'
	}

	buf := make([]byte, 2<<10)
	for i := 0; i < b.N; i++ {
		if _, err := sendConn.WriteTo(sendBuf, dstAddr); err != nil {
			b.Fatalf("WriteTo: %v", err)
		}
		if _, _, err := recvConnUDP.ReadFromUDP(buf); err != nil {
			b.Fatalf("ReadFromUDP: %v", err)
		}
	}
}

// Test that a netmap update where node changes its node key but
// doesn't change its disco key doesn't result in a broken state.
//
// https://github.com/tailscale/tailscale/issues/1391
func TestSetNetworkMapChangingNodeKey(t *testing.T) {
	conn := newTestConn(t)
	t.Cleanup(func() { conn.Close() })
	var buf tstest.MemLogger
	conn.logf = buf.Logf

	conn.SetPrivateKey(key.NodePrivateFromRaw32(mem.B([]byte{0: 1, 31: 0})))

	discoKey := key.DiscoPublicFromRaw32(mem.B([]byte{31: 1}))
	nodeKey1 := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 2: '1', 31: 0}))
	nodeKey2 := key.NodePublicFromRaw32(mem.B([]byte{0: 'N', 1: 'K', 2: '2', 31: 0}))

	conn.SetNetworkMap(&netmap.NetworkMap{
		Peers: []*tailcfg.Node{
			{
				Key:       nodeKey1,
				DiscoKey:  discoKey,
				Endpoints: []string{"192.168.1.2:345"},
			},
		},
	})
	_, err := conn.ParseEndpoint(nodeKey1.UntypedHexString())
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		conn.SetNetworkMap(&netmap.NetworkMap{
			Peers: []*tailcfg.Node{
				{
					Key:       nodeKey2,
					DiscoKey:  discoKey,
					Endpoints: []string{"192.168.1.2:345"},
				},
			},
		})
	}

	de, ok := conn.peerMap.endpointForNodeKey(nodeKey2)
	if ok && de.publicKey != nodeKey2 {
		t.Fatalf("discoEndpoint public key = %q; want %q", de.publicKey, nodeKey2)
	}
	deDisco := de.disco.Load()
	if deDisco == nil {
		t.Fatalf("discoEndpoint disco is nil")
	}
	if deDisco.key != discoKey {
		t.Errorf("discoKey = %v; want %v", deDisco.key, discoKey)
	}
	if _, ok := conn.peerMap.endpointForNodeKey(nodeKey1); ok {
		t.Errorf("didn't expect to find node for key1")
	}

	log := buf.String()
	wantSub := map[string]int{
		"magicsock: got updated network map; 1 peers": 2,
	}
	for sub, want := range wantSub {
		got := strings.Count(log, sub)
		if got != want {
			t.Errorf("in log, count of substring %q = %v; want %v", sub, got, want)
		}
	}
	if t.Failed() {
		t.Logf("log output: %s", log)
	}
}

func TestRebindStress(t *testing.T) {
	conn := newTestConn(t)

	var buf tstest.MemLogger
	conn.logf = buf.Logf

	closed := false
	t.Cleanup(func() {
		if !closed {
			conn.Close()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)
	go func() {
		buffs := make([][]byte, 1)
		sizes := make([]int, 1)
		eps := make([]wgconn.Endpoint, 1)
		buffs[0] = make([]byte, 1500)
		receiveIPv4 := conn.receiveIPv4()
		for {
			_, err := receiveIPv4(buffs, sizes, eps)
			if ctx.Err() != nil {
				errc <- nil
				return
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			conn.Rebind()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			conn.Rebind()
		}
	}()
	wg.Wait()

	cancel()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true

	err := <-errc
	if err != nil {
		t.Fatalf("Got ReceiveIPv4 error: %v (is closed = %v). Log:\n%s", err, errors.Is(err, net.ErrClosed), buf.String())
	}
}

func TestEndpointSetsEqual(t *testing.T) {
	s := func(ports ...uint16) (ret []tailcfg.Endpoint) {
		for _, port := range ports {
			ret = append(ret, tailcfg.Endpoint{
				Addr: netip.AddrPortFrom(netip.Addr{}, port),
			})
		}
		return
	}
	tests := []struct {
		a, b []tailcfg.Endpoint
		want bool
	}{
		{
			want: true,
		},
		{
			a:    s(1, 2, 3),
			b:    s(1, 2, 3),
			want: true,
		},
		{
			a:    s(1, 2),
			b:    s(2, 1),
			want: true,
		},
		{
			a:    s(1, 2),
			b:    s(2, 1, 1),
			want: true,
		},
		{
			a:    s(1, 2, 2),
			b:    s(2, 1),
			want: true,
		},
		{
			a:    s(1, 2, 2),
			b:    s(2, 1, 1),
			want: true,
		},
		{
			a:    s(1, 2, 2, 3),
			b:    s(2, 1, 1),
			want: false,
		},
		{
			a:    s(1, 2, 2),
			b:    s(2, 1, 1, 3),
			want: false,
		},
	}
	for _, tt := range tests {
		if got := endpointSetsEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("%q vs %q = %v; want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestBetterAddr(t *testing.T) {
	const ms = time.Millisecond
	al := func(ipps string, d time.Duration) addrLatency {
		return addrLatency{netip.MustParseAddrPort(ipps), d}
	}
	zero := addrLatency{}

	const (
		publicV4   = "1.2.3.4:555"
		publicV4_2 = "5.6.7.8:999"
		publicV6   = "[2001::5]:123"

		privateV4 = "10.0.0.2:123"
	)

	tests := []struct {
		a, b addrLatency
		want bool // whether a is better than b
	}{
		{a: zero, b: zero, want: false},
		{a: al(publicV4, 5*ms), b: zero, want: true},
		{a: zero, b: al(publicV4, 5*ms), want: false},
		{a: al(publicV4, 5*ms), b: al(publicV4_2, 10*ms), want: true},
		{a: al(publicV4, 5*ms), b: al(publicV4, 10*ms), want: false}, // same IPPort

		// Don't prefer b to a if it's not substantially better.
		{a: al(publicV4, 100*ms), b: al(publicV4_2, 100*ms), want: false},
		{a: al(publicV4, 100*ms), b: al(publicV4_2, 101*ms), want: false},
		{a: al(publicV4, 100*ms), b: al(publicV4_2, 103*ms), want: true},

		// Latencies of zero don't result in a divide-by-zero
		{a: al(publicV4, 0), b: al(publicV4_2, 0), want: false},

		// Prefer private IPs to public IPs if roughly equivalent...
		{
			a:    al(privateV4, 100*ms),
			b:    al(publicV4, 91*ms),
			want: true,
		},
		{
			a:    al(publicV4, 91*ms),
			b:    al(privateV4, 100*ms),
			want: false,
		},
		// ... but not if the private IP is slower.
		{
			a:    al(privateV4, 100*ms),
			b:    al(publicV4, 30*ms),
			want: false,
		},
		{
			a:    al(publicV4, 30*ms),
			b:    al(privateV4, 100*ms),
			want: true,
		},

		// Prefer IPv6 if roughly equivalent:
		{
			a:    al(publicV6, 100*ms),
			b:    al(publicV4, 91*ms),
			want: true,
		},
		{
			a:    al(publicV4, 91*ms),
			b:    al(publicV6, 100*ms),
			want: false,
		},
		// But not if IPv4 is much faster:
		{
			a:    al(publicV6, 100*ms),
			b:    al(publicV4, 30*ms),
			want: false,
		},
		{
			a:    al(publicV4, 30*ms),
			b:    al(publicV6, 100*ms),
			want: true,
		},

		// Private IPs are preferred over public IPs even if the public
		// IP is IPv6.
		{
			a:    al("192.168.0.1:555", 100*ms),
			b:    al("[2001::5]:123", 101*ms),
			want: true,
		},
		{
			a:    al("[2001::5]:123", 101*ms),
			b:    al("192.168.0.1:555", 100*ms),
			want: false,
		},
	}
	for i, tt := range tests {
		got := betterAddr(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("[%d] betterAddr(%+v, %+v) = %v; want %v", i, tt.a, tt.b, got, tt.want)
			continue
		}
		gotBack := betterAddr(tt.b, tt.a)
		if got && gotBack {
			t.Errorf("[%d] betterAddr(%+v, %+v) and betterAddr(%+v, %+v) both unexpectedly true", i, tt.a, tt.b, tt.b, tt.a)
		}
	}
}

func epStrings(eps []tailcfg.Endpoint) (ret []string) {
	for _, ep := range eps {
		ret = append(ret, ep.Addr.String())
	}
	return
}

func TestStressSetNetworkMap(t *testing.T) {
	t.Parallel()

	conn := newTestConn(t)
	t.Cleanup(func() { conn.Close() })
	var buf tstest.MemLogger
	conn.logf = buf.Logf

	conn.SetPrivateKey(key.NewNode())

	const npeers = 5
	present := make([]bool, npeers)
	allPeers := make([]*tailcfg.Node, npeers)
	for i := range allPeers {
		present[i] = true
		allPeers[i] = &tailcfg.Node{
			DiscoKey:  randDiscoKey(),
			Key:       randNodeKey(),
			Endpoints: []string{fmt.Sprintf("192.168.1.2:%d", i)},
		}
	}

	// Get a PRNG seed. If not provided, generate a new one to get extra coverage.
	seed, err := strconv.ParseUint(os.Getenv("TS_STRESS_SET_NETWORK_MAP_SEED"), 10, 64)
	if err != nil {
		var buf [8]byte
		crand.Read(buf[:])
		seed = binary.LittleEndian.Uint64(buf[:])
	}
	t.Logf("TS_STRESS_SET_NETWORK_MAP_SEED=%d", seed)
	prng := rand.New(rand.NewSource(int64(seed)))

	const iters = 1000 // approx 0.5s on an m1 mac
	for i := 0; i < iters; i++ {
		for j := 0; j < npeers; j++ {
			// Randomize which peers are present.
			if prng.Int()&1 == 0 {
				present[j] = !present[j]
			}
			// Randomize some peer disco keys and node keys.
			if prng.Int()&1 == 0 {
				allPeers[j].DiscoKey = randDiscoKey()
			}
			if prng.Int()&1 == 0 {
				allPeers[j].Key = randNodeKey()
			}
		}
		// Clone existing peers into a new netmap.
		peers := make([]*tailcfg.Node, 0, len(allPeers))
		for peerIdx, p := range allPeers {
			if present[peerIdx] {
				peers = append(peers, p.Clone())
			}
		}
		// Set the netmap.
		conn.SetNetworkMap(&netmap.NetworkMap{
			Peers: peers,
		})
		// Check invariants.
		if err := conn.peerMap.validate(); err != nil {
			t.Error(err)
		}
	}
}

func randDiscoKey() (k key.DiscoPublic) { return key.NewDisco().Public() }
func randNodeKey() (k key.NodePublic)   { return key.NewNode().Public() }

// validate checks m for internal consistency and reports the first error encountered.
// It is used in tests only, so it doesn't need to be efficient.
func (m *peerMap) validate() error {
	seenEps := make(map[*endpoint]bool)
	for pub, pi := range m.byNodeKey {
		if got := pi.ep.publicKey; got != pub {
			return fmt.Errorf("byNodeKey[%v].publicKey = %v", pub, got)
		}
		if _, ok := seenEps[pi.ep]; ok {
			return fmt.Errorf("duplicate endpoint present: %v", pi.ep.publicKey)
		}
		seenEps[pi.ep] = true
		for ipp, v := range pi.ipPorts {
			if !v {
				return fmt.Errorf("m.byIPPort[%v] is false, expected map to be set-like", ipp)
			}
			if got := m.byIPPort[ipp]; got != pi {
				return fmt.Errorf("m.byIPPort[%v] = %v, want %v", ipp, got, pi)
			}
		}
	}

	for ipp, pi := range m.byIPPort {
		if !pi.ipPorts[ipp] {
			return fmt.Errorf("ipPorts[%v] for %v is false", ipp, pi.ep.publicKey)
		}
		pi2 := m.byNodeKey[pi.ep.publicKey]
		if pi != pi2 {
			return fmt.Errorf("byNodeKey[%v]=%p doesn't match byIPPort[%v]=%p", pi, pi, pi.ep.publicKey, pi2)
		}
	}

	publicToDisco := make(map[key.NodePublic]key.DiscoPublic)
	for disco, nodes := range m.nodesOfDisco {
		for pub, v := range nodes {
			if !v {
				return fmt.Errorf("m.nodeOfDisco[%v][%v] is false, expected map to be set-like", disco, pub)
			}
			if _, ok := m.byNodeKey[pub]; !ok {
				return fmt.Errorf("nodesOfDisco refers to public key %v, which is not present in byNodeKey", pub)
			}
			if _, ok := publicToDisco[pub]; ok {
				return fmt.Errorf("publicKey %v refers to multiple disco keys", pub)
			}
			publicToDisco[pub] = disco
		}
	}

	return nil
}

func TestBlockForeverConnUnblocks(t *testing.T) {
	c := newBlockForeverConn()
	done := make(chan error, 1)
	go func() {
		defer close(done)
		_, _, err := c.ReadFromUDPAddrPort(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // give ReadFrom time to get blocked
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Errorf("got %v; want net.ErrClosed", err)
		}
	case <-timer.C:
		t.Fatal("timeout")
	}
}

func TestDiscoMagicMatches(t *testing.T) {
	// Convert our disco magic number into a uint32 and uint16 to test
	// against. We panic on an incorrect length here rather than try to be
	// generic with our BPF instructions below.
	//
	// Note that BPF uses network byte order (big-endian) when loading data
	// from a packet, so that is what we use to generate our magic numbers.
	if len(disco.Magic) != 6 {
		t.Fatalf("expected disco.Magic to be of length 6")
	}
	if m1 := binary.BigEndian.Uint32([]byte(disco.Magic[:4])); m1 != discoMagic1 {
		t.Errorf("first 4 bytes of disco magic don't match, got %v want %v", discoMagic1, m1)
	}
	if m2 := binary.BigEndian.Uint16([]byte(disco.Magic[4:6])); m2 != discoMagic2 {
		t.Errorf("last 2 bytes of disco magic don't match, got %v want %v", discoMagic2, m2)
	}
}

func TestRebindingUDPConn(t *testing.T) {
	// Test that RebindingUDPConn can be re-bound to different connection
	// types.
	c := RebindingUDPConn{}
	realConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer realConn.Close()
	c.setConnLocked(realConn.(nettype.PacketConn), "udp4", 1)
	c.setConnLocked(newBlockForeverConn(), "", 1)
}

// https://github.com/tailscale/tailscale/issues/6680: don't ignore
// SetNetworkMap calls when there are no peers. (A too aggressive fast path was
// previously bailing out early, thinking there were no changes since all zero
// peers didn't change, but the netmap has non-peer info in it too we shouldn't discard)
func TestSetNetworkMapWithNoPeers(t *testing.T) {
	var c Conn
	c.logf = logger.Discard

	for i := 1; i <= 3; i++ {
		nm := &netmap.NetworkMap{}
		c.SetNetworkMap(nm)
		t.Logf("ptr %d: %p", i, nm)
		if c.netMap != nm {
			t.Fatalf("call %d: didn't store netmap", i)
		}
	}
}

func TestBufferedDerpWritesBeforeDrop(t *testing.T) {
	vv := bufferedDerpWritesBeforeDrop()
	if vv < 32 {
		t.Fatalf("got bufferedDerpWritesBeforeDrop=%d, which is < 32", vv)
	}
	t.Logf("bufferedDerpWritesBeforeDrop = %d", vv)
}

func setGSOSize(control *[]byte, gsoSize uint16) {
	*control = (*control)[:cap(*control)]
	binary.LittleEndian.PutUint16(*control, gsoSize)
}

func getGSOSize(control []byte) (int, error) {
	if len(control) < 2 {
		return 0, nil
	}
	return int(binary.LittleEndian.Uint16(control)), nil
}

func Test_batchingUDPConn_splitCoalescedMessages(t *testing.T) {
	c := &batchingUDPConn{
		setGSOSizeInControl:   setGSOSize,
		getGSOSizeFromControl: getGSOSize,
	}

	newMsg := func(n, gso int) ipv6.Message {
		msg := ipv6.Message{
			Buffers: [][]byte{make([]byte, 1024)},
			N:       n,
			OOB:     make([]byte, 2),
		}
		binary.LittleEndian.PutUint16(msg.OOB, uint16(gso))
		if gso > 0 {
			msg.NN = 2
		}
		return msg
	}

	cases := []struct {
		name        string
		msgs        []ipv6.Message
		firstMsgAt  int
		wantNumEval int
		wantMsgLens []int
		wantErr     bool
	}{
		{
			name: "second last split last empty",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(3, 1),
				newMsg(0, 0),
			},
			firstMsgAt:  2,
			wantNumEval: 3,
			wantMsgLens: []int{1, 1, 1, 0},
			wantErr:     false,
		},
		{
			name: "second last no split last empty",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(0, 0),
			},
			firstMsgAt:  2,
			wantNumEval: 1,
			wantMsgLens: []int{1, 0, 0, 0},
			wantErr:     false,
		},
		{
			name: "second last no split last no split",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(1, 0),
			},
			firstMsgAt:  2,
			wantNumEval: 2,
			wantMsgLens: []int{1, 1, 0, 0},
			wantErr:     false,
		},
		{
			name: "second last no split last split",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(3, 1),
			},
			firstMsgAt:  2,
			wantNumEval: 4,
			wantMsgLens: []int{1, 1, 1, 1},
			wantErr:     false,
		},
		{
			name: "second last split last split",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(2, 1),
				newMsg(2, 1),
			},
			firstMsgAt:  2,
			wantNumEval: 4,
			wantMsgLens: []int{1, 1, 1, 1},
			wantErr:     false,
		},
		{
			name: "second last no split last split overflow",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(4, 1),
			},
			firstMsgAt:  2,
			wantNumEval: 4,
			wantMsgLens: []int{1, 1, 1, 1},
			wantErr:     true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.splitCoalescedMessages(tt.msgs, 2)
			if err != nil && !tt.wantErr {
				t.Fatalf("err: %v", err)
			}
			if got != tt.wantNumEval {
				t.Fatalf("got to eval: %d want: %d", got, tt.wantNumEval)
			}
			for i, msg := range tt.msgs {
				if msg.N != tt.wantMsgLens[i] {
					t.Fatalf("msg[%d].N: %d want: %d", i, msg.N, tt.wantMsgLens[i])
				}
			}
		})
	}
}

func Test_batchingUDPConn_coalesceMessages(t *testing.T) {
	c := &batchingUDPConn{
		setGSOSizeInControl:   setGSOSize,
		getGSOSizeFromControl: getGSOSize,
	}

	cases := []struct {
		name     string
		buffs    [][]byte
		wantLens []int
		wantGSO  []int
	}{
		{
			name: "one message no coalesce",
			buffs: [][]byte{
				make([]byte, 1, 1),
			},
			wantLens: []int{1},
			wantGSO:  []int{0},
		},
		{
			name: "two messages equal len coalesce",
			buffs: [][]byte{
				make([]byte, 1, 2),
				make([]byte, 1, 1),
			},
			wantLens: []int{2},
			wantGSO:  []int{1},
		},
		{
			name: "two messages unequal len coalesce",
			buffs: [][]byte{
				make([]byte, 2, 3),
				make([]byte, 1, 1),
			},
			wantLens: []int{3},
			wantGSO:  []int{2},
		},
		{
			name: "three messages second unequal len coalesce",
			buffs: [][]byte{
				make([]byte, 2, 3),
				make([]byte, 1, 1),
				make([]byte, 2, 2),
			},
			wantLens: []int{3, 2},
			wantGSO:  []int{2, 0},
		},
		{
			name: "three messages limited cap coalesce",
			buffs: [][]byte{
				make([]byte, 2, 4),
				make([]byte, 2, 2),
				make([]byte, 2, 2),
			},
			wantLens: []int{4, 2},
			wantGSO:  []int{2, 0},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			addr := &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 1,
			}
			msgs := make([]ipv6.Message, len(tt.buffs))
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, 0, 2)
			}
			got := c.coalesceMessages(addr, tt.buffs, msgs)
			if got != len(tt.wantLens) {
				t.Fatalf("got len %d want: %d", got, len(tt.wantLens))
			}
			for i := 0; i < got; i++ {
				if msgs[i].Addr != addr {
					t.Errorf("msgs[%d].Addr != passed addr", i)
				}
				gotLen := len(msgs[i].Buffers[0])
				if gotLen != tt.wantLens[i] {
					t.Errorf("len(msgs[%d].Buffers[0]) %d != %d", i, gotLen, tt.wantLens[i])
				}
				gotGSO, err := getGSOSize(msgs[i].OOB)
				if err != nil {
					t.Fatalf("msgs[%d] getGSOSize err: %v", i, err)
				}
				if gotGSO != tt.wantGSO[i] {
					t.Errorf("msgs[%d] gsoSize %d != %d", i, gotGSO, tt.wantGSO[i])
				}
			}
		})
	}
}

// newWireguard starts up a new wireguard-go device attached to a test tun, and
// returns the device, tun and endpoint port. To add peers call device.IpcSet with UAPI instructions.
func newWireguard(t *testing.T, uapi string, aips []netip.Prefix) (*device.Device, *tuntest.ChannelTUN, uint16) {
	wgtun := tuntest.NewChannelTUN()
	wglogf := func(f string, args ...any) {
		t.Logf("wg-go: "+f, args...)
	}
	wglog := device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   wglogf,
	}
	wgdev := wgcfg.NewDevice(wgtun.TUN(), wgconn.NewDefaultBind(), &wglog)

	if err := wgdev.IpcSet(uapi); err != nil {
		t.Fatal(err)
	}

	if err := wgdev.Up(); err != nil {
		t.Fatal(err)
	}

	var port uint16
	s, err := wgdev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if k == "listen_port" {
			p, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				panic(err)
			}
			port = uint16(p)
			break
		}
	}

	return wgdev, wgtun, port
}

func TestIsWireGuardOnlyPeer(t *testing.T) {
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	tskey := key.NewNode()
	tsaip := netip.MustParsePrefix("100.111.222.111/32")

	wgkey := key.NewNode()
	wgaip := netip.MustParsePrefix("100.222.111.222/32")

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\n\n",
		wgkey.UntypedHexString(), tskey.Public().UntypedHexString(), tsaip.String())
	wgdev, wgtun, port := newWireguard(t, uapi, []netip.Prefix{wgaip})
	defer wgdev.Close()
	wgEp := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	m := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, tskey)
	defer m.Close()

	nm := &netmap.NetworkMap{
		Name:       "ts",
		PrivateKey: m.privateKey,
		NodeKey:    m.privateKey.Public(),
		Addresses:  []netip.Prefix{tsaip},
		Peers: []*tailcfg.Node{
			{
				Key:             wgkey.Public(),
				Endpoints:       []string{wgEp.String()},
				IsWireGuardOnly: true,
				Addresses:       []netip.Prefix{wgaip},
				AllowedIPs:      []netip.Prefix{wgaip},
			},
		},
	}
	m.conn.SetNetworkMap(nm)

	cfg, err := nmcfg.WGCfg(nm, t.Logf, netmap.AllowSingleHosts|netmap.AllowSubnetRoutes, "")
	if err != nil {
		t.Fatal(err)
	}
	m.Reconfig(cfg)

	pbuf := tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- pbuf

	select {
	case p := <-wgtun.Inbound:
		if !bytes.Equal(p, pbuf) {
			t.Errorf("got unexpected packet: %x", p)
		}
	case <-time.After(time.Second):
		t.Fatal("no packet after 1s")
	}
}

func TestIsWireGuardOnlyPeerWithMasquerade(t *testing.T) {
	t.Skip("Coder: We do not support wireguard only peers, and this test fails because we currently only support IPv6 addresses for TS IPs")

	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	tskey := key.NewNode()
	tsaip := netip.MustParsePrefix("100.111.222.111/32")

	wgkey := key.NewNode()
	wgaip := netip.MustParsePrefix("10.64.0.1/32")

	// the ip that the wireguard peer has in allowed ips and expects as a masq source
	masqip := netip.MustParsePrefix("10.64.0.2/32")

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\n\n",
		wgkey.UntypedHexString(), tskey.Public().UntypedHexString(), masqip.String())
	wgdev, wgtun, port := newWireguard(t, uapi, []netip.Prefix{wgaip})
	defer wgdev.Close()
	wgEp := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	m := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, tskey)
	defer m.Close()

	nm := &netmap.NetworkMap{
		Name:       "ts",
		PrivateKey: m.privateKey,
		NodeKey:    m.privateKey.Public(),
		Addresses:  []netip.Prefix{tsaip},
		Peers: []*tailcfg.Node{
			{
				Key:                           wgkey.Public(),
				Endpoints:                     []string{wgEp.String()},
				IsWireGuardOnly:               true,
				Addresses:                     []netip.Prefix{wgaip},
				AllowedIPs:                    []netip.Prefix{wgaip},
				SelfNodeV4MasqAddrForThisPeer: ptr.To(masqip.Addr()),
			},
		},
	}
	m.conn.SetNetworkMap(nm)

	cfg, err := nmcfg.WGCfg(nm, t.Logf, netmap.AllowSingleHosts|netmap.AllowSubnetRoutes, "")
	if err != nil {
		t.Fatal(err)
	}
	m.Reconfig(cfg)

	pbuf := tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- pbuf

	select {
	case p := <-wgtun.Inbound:

		// TODO(raggi): move to a bytes.Equal based test later, once
		// tuntest.Ping produces correct checksums!

		var pkt packet.Parsed
		pkt.Decode(p)
		if pkt.ICMP4Header().Type != packet.ICMP4EchoRequest {
			t.Fatalf("unexpected packet: %x", p)
		}
		if pkt.Src.Addr() != masqip.Addr() {
			t.Fatalf("bad source IP, got %s, want %s", pkt.Src.Addr(), masqip.Addr())
		}
		if pkt.Dst.Addr() != wgaip.Addr() {
			t.Fatalf("bad source IP, got %s, want %s", pkt.Src.Addr(), masqip.Addr())
		}
	case <-time.After(time.Second):
		t.Fatal("no packet after 1s")
	}
}

func TestEndpointTracker(t *testing.T) {
	local := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("192.168.1.1:12345"),
		Type: tailcfg.EndpointLocal,
	}

	stun4_1 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("1.2.3.4:12345"),
		Type: tailcfg.EndpointSTUN,
	}
	stun4_2 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("5.6.7.8:12345"),
		Type: tailcfg.EndpointSTUN,
	}

	stun6_1 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("[2a09:8280:1::1111]:12345"),
		Type: tailcfg.EndpointSTUN,
	}
	stun6_2 := tailcfg.Endpoint{
		Addr: netip.MustParseAddrPort("[2a09:8280:1::2222]:12345"),
		Type: tailcfg.EndpointSTUN,
	}

	start := time.Unix(1681503440, 0)

	steps := []struct {
		name string
		now  time.Time
		eps  []tailcfg.Endpoint
		want []tailcfg.Endpoint
	}{
		{
			name: "initial endpoints",
			now:  start,
			eps:  []tailcfg.Endpoint{local, stun4_1, stun6_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "no change",
			now:  start.Add(1 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun4_1, stun6_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "missing stun4",
			now:  start.Add(2 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun6_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "missing stun6",
			now:  start.Add(3 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun4_1},
			want: []tailcfg.Endpoint{local, stun4_1, stun6_1},
		},
		{
			name: "multiple STUN addresses within timeout",
			now:  start.Add(4 * time.Minute),
			eps:  []tailcfg.Endpoint{local, stun4_2, stun6_2},
			want: []tailcfg.Endpoint{local, stun4_1, stun4_2, stun6_1, stun6_2},
		},
		{
			name: "endpoint extended",
			now:  start.Add(3*time.Minute + endpointTrackerLifetime - 1),
			eps:  []tailcfg.Endpoint{local},
			want: []tailcfg.Endpoint{
				local, stun4_2, stun6_2,
				// stun4_1 had its lifetime extended by the
				// "missing stun6" test above to that start
				// time plus the lifetime, while stun6 should
				// have expired a minute sooner. It should thus
				// be in this returned list.
				stun4_1,
			},
		},
		{
			name: "after timeout",
			now:  start.Add(4*time.Minute + endpointTrackerLifetime + 1),
			eps:  []tailcfg.Endpoint{local, stun4_2, stun6_2},
			want: []tailcfg.Endpoint{local, stun4_2, stun6_2},
		},
		{
			name: "after timeout still caches",
			now:  start.Add(4*time.Minute + endpointTrackerLifetime + time.Minute),
			eps:  []tailcfg.Endpoint{local},
			want: []tailcfg.Endpoint{local, stun4_2, stun6_2},
		},
	}

	var et endpointTracker
	for _, tt := range steps {
		t.Logf("STEP: %s", tt.name)

		got := et.update(tt.now, tt.eps)

		// Sort both arrays for comparison
		slices.SortFunc(got, func(a, b tailcfg.Endpoint) int {
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})
		slices.SortFunc(tt.want, func(a, b tailcfg.Endpoint) int {
			return strings.Compare(a.Addr.String(), b.Addr.String())
		})

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("endpoints mismatch\ngot: %+v\nwant: %+v", got, tt.want)
		}
	}
}

// applyNetworkMap is a test helper that sets the network map and
// configures WG.
func applyNetworkMap(t *testing.T, m *magicStack, nm *netmap.NetworkMap) {
	t.Helper()
	m.conn.SetNetworkMap(nm)
	// Make sure we can't use v6 to avoid test failures.
	m.conn.noV6.Store(true)

	// Turn the network map into a wireguard config (for the tailscale internal wireguard device).
	cfg, err := nmcfg.WGCfg(nm, t.Logf, netmap.AllowSingleHosts|netmap.AllowSubnetRoutes, "")
	if err != nil {
		t.Fatal(err)
	}
	// Apply the wireguard config to the tailscale internal wireguard device.
	if err := m.Reconfig(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestIsWireGuardOnlyPickEndpointByPing(t *testing.T) {
	t.Skip("This test is flaky; see https://github.com/tailscale/tailscale/issues/8037")

	clock := &tstest.Clock{}
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	// Create a TS client.
	tskey := key.NewNode()
	tsaip := netip.MustParsePrefix("100.111.222.111/32")

	// Create a WireGuard only client.
	wgkey := key.NewNode()
	wgaip := netip.MustParsePrefix("100.222.111.222/32")

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s\n\n",
		wgkey.UntypedHexString(), tskey.Public().UntypedHexString(), tsaip.String())

	wgdev, wgtun, port := newWireguard(t, uapi, []netip.Prefix{wgaip})
	defer wgdev.Close()
	wgEp := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	wgEp2 := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port)

	m := newMagicStackWithKey(t, t.Logf, localhostListener{}, derpMap, tskey)
	defer m.Close()

	pr := newPingResponder(t)
	// Get a destination address which includes a port, so that UDP packets flow
	// to the correct place, the mockPinger will use this to direct port-less
	// pings to this place.
	pingDest := pr.LocalAddr()

	// Create and start the pinger that is used for the
	// wireguard only endpoint pings
	p, closeP := mockPinger(t, clock, pingDest)
	defer closeP()
	m.conn.wgPinger.Set(p)

	// Create an IPv6 endpoint which should not receive any traffic.
	v6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	badEpRecv := make(chan []byte)
	go func() {
		defer v6.Close()
		for {
			b := make([]byte, 1500)
			n, _, err := v6.ReadFrom(b)
			if err != nil {
				close(badEpRecv)
				return
			}
			badEpRecv <- b[:n]
		}
	}()
	wgEpV6 := netip.MustParseAddrPort(v6.LocalAddr().String())

	nm := &netmap.NetworkMap{
		Name:       "ts",
		PrivateKey: m.privateKey,
		NodeKey:    m.privateKey.Public(),
		Addresses:  []netip.Prefix{tsaip},
		Peers: []*tailcfg.Node{
			{
				Key:             wgkey.Public(),
				Endpoints:       []string{wgEp.String(), wgEp2.String(), wgEpV6.String()},
				IsWireGuardOnly: true,
				Addresses:       []netip.Prefix{wgaip},
				AllowedIPs:      []netip.Prefix{wgaip},
			},
		},
	}

	applyNetworkMap(t, m, nm)

	buf := tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- buf

	select {
	case p := <-wgtun.Inbound:
		if !bytes.Equal(p, buf) {
			t.Errorf("got unexpected packet: %x", p)
		}
	case <-badEpRecv:
		t.Fatal("got packet on bad endpoint")
	case <-time.After(5 * time.Second):
		t.Fatal("no packet after 1s")
	}

	pi, ok := m.conn.peerMap.byNodeKey[wgkey.Public()]
	if !ok {
		t.Fatal("wgkey doesn't exist in peer map")
	}

	// Check that we got a valid address set on the first send - this
	// will be randomly selected, but because we have noV6 set to true,
	// it will be the IPv4 address.
	if !pi.ep.bestAddr.Addr().IsValid() {
		t.Fatal("bestaddr was nil")
	}

	if pi.ep.trustBestAddrUntil.Before(mono.Now().Add(14 * time.Second)) {
		t.Errorf("trustBestAddrUntil time wasn't set to 15 seconds in the future: got %v", pi.ep.trustBestAddrUntil)
	}

	for ipp, state := range pi.ep.endpointState {
		if ipp == wgEp {
			if len(state.recentPongs) != 1 {
				t.Errorf("IPv4 address did not have a recentPong entry: got %v, want %v", len(state.recentPongs), 1)
			}
			// Set the latency extremely low so we choose this endpoint during the next
			// addrForSendLocked call.
			state.recentPongs[state.recentPong].latency = time.Nanosecond
		}

		if ipp == wgEp2 {
			if len(state.recentPongs) != 1 {
				t.Errorf("IPv4 address did not have a recentPong entry: got %v, want %v", len(state.recentPongs), 1)
			}
			// Set the latency extremely high so we dont choose endpoint during the next
			// addrForSendLocked call.
			state.recentPongs[state.recentPong].latency = time.Second
		}

		if ipp == wgEpV6 && len(state.recentPongs) != 0 {
			t.Fatal("IPv6 should not have recentPong: IPv6 is not useable")
		}
	}

	// Set trustBestAddrUnitl to now, so addrForSendLocked goes through the
	// latency selection flow.
	pi.ep.trustBestAddrUntil = mono.Now().Add(-time.Second)

	buf = tuntest.Ping(wgaip.Addr(), tsaip.Addr())
	m.tun.Outbound <- buf

	select {
	case p := <-wgtun.Inbound:
		if !bytes.Equal(p, buf) {
			t.Errorf("got unexpected packet: %x", p)
		}
	case <-badEpRecv:
		t.Fatal("got packet on bad endpoint")
	case <-time.After(5 * time.Second):
		t.Fatal("no packet after 1s")
	}

	// Check that we have responded to a WireGuard only ping twice.
	if pr.responseCount != 2 {
		t.Fatal("pingresponder response count was not 2", pr.responseCount)
	}

	pi, ok = m.conn.peerMap.byNodeKey[wgkey.Public()]
	if !ok {
		t.Fatal("wgkey doesn't exist in peer map")
	}

	if !pi.ep.bestAddr.Addr().IsValid() {
		t.Error("no bestAddr address was set")
	}

	if pi.ep.bestAddr.Addr() != wgEp.Addr() {
		t.Errorf("bestAddr was not set to the expected IPv4 address: got %v, want %v", pi.ep.bestAddr.Addr().String(), wgEp.Addr())
	}

	if pi.ep.trustBestAddrUntil.IsZero() {
		t.Fatal("trustBestAddrUntil was not set")
	}

	if pi.ep.trustBestAddrUntil.Before(mono.Now().Add(55 * time.Minute)) {
		// Set to 55 minutes incase of sloooow tests.
		t.Errorf("trustBestAddrUntil time wasn't set to an hour in the future: got %v", pi.ep.trustBestAddrUntil)
	}
}

// udpingPacketConn will convert potentially ICMP destination addrs to UDP
// destination addrs in WriteTo so that a test that is intending to send ICMP
// traffic will instead send UDP traffic, without the higher level Pinger being
// aware of this difference.
type udpingPacketConn struct {
	net.PacketConn
	// destPort will be configured by the test to be the peer expected to respond to a ping.
	destPort uint16
}

func (u *udpingPacketConn) WriteTo(body []byte, dest net.Addr) (int, error) {
	switch d := dest.(type) {
	case *net.IPAddr:
		udpAddr := &net.UDPAddr{
			IP:   d.IP,
			Port: int(u.destPort),
			Zone: d.Zone,
		}
		return u.PacketConn.WriteTo(body, udpAddr)
	}
	return 0, fmt.Errorf("unimplemented udpingPacketConn for %T", dest)
}

type mockListenPacketer struct {
	conn4 net.PacketConn
	conn6 net.PacketConn
}

func (mlp *mockListenPacketer) ListenPacket(ctx context.Context, typ string, addr string) (net.PacketConn, error) {
	switch typ {
	case "ip4:icmp":
		return mlp.conn4, nil
	case "ip6:icmp":
		return mlp.conn6, nil
	}
	return nil, fmt.Errorf("unimplemented ListenPacketForTesting for %s", typ)
}

func mockPinger(t *testing.T, clock *tstest.Clock, dest net.Addr) (*ping.Pinger, func()) {
	ctx := context.Background()

	dIPP := netip.MustParseAddrPort(dest.String())
	// In tests, we use UDP so that we can test without being root; this
	// doesn't matter because we mock out the ICMP reply below to be a real
	// ICMP echo reply packet.
	conn4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}
	conn6, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}

	conn4 = &udpingPacketConn{
		PacketConn: conn4,
		destPort:   dIPP.Port(),
	}

	conn6 = &udpingPacketConn{
		PacketConn: conn6,
		destPort:   dIPP.Port(),
	}

	p := ping.New(ctx, t.Logf, &mockListenPacketer{conn4: conn4, conn6: conn6})

	done := func() {
		if err := p.Close(); err != nil {
			t.Errorf("error on close: %v", err)
		}
	}

	return p, done
}

type pingResponder struct {
	net.PacketConn
	running       atomic.Bool
	responseCount int
}

func (p *pingResponder) start() {
	buf := make([]byte, 1500)
	for p.running.Load() {
		n, addr, err := p.PacketConn.ReadFrom(buf)
		if err != nil {
			return
		}

		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			panic("got a non-ICMP message:" + fmt.Sprintf("%x", m))
		}

		r := icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: m.Code,
			Body: m.Body,
		}

		b, err := r.Marshal(nil)
		if err != nil {
			panic(err)
		}

		if _, err := p.PacketConn.WriteTo(b, addr); err != nil {
			panic(err)
		}
		p.responseCount++
	}
}

func (p *pingResponder) stop() {
	p.running.Store(false)
	p.Close()
}

func newPingResponder(t *testing.T) *pingResponder {
	t.Helper()
	// global binds should be both IPv4 and IPv6 (if our test platforms don't,
	// we might need to bind two sockets instead)
	conn, err := net.ListenPacket("udp", ":")
	if err != nil {
		t.Fatal(err)
	}
	pr := &pingResponder{PacketConn: conn}
	pr.running.Store(true)
	go pr.start()
	t.Cleanup(pr.stop)
	return pr
}

func TestAddrForSendLockedForWireGuardOnly(t *testing.T) {
	testTime := mono.Now()

	type endpointDetails struct {
		addrPort netip.AddrPort
		latency  time.Duration
	}

	wgTests := []struct {
		name       string
		noV4       bool
		noV6       bool
		sendWGPing bool
		ep         []endpointDetails
		want       netip.AddrPort
	}{
		{
			name:       "choose lowest latency for useable IPv4 and IPv6",
			sendWGPing: true,
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
				{
					addrPort: netip.MustParseAddrPort("[2345:0425:2CA1:0000:0000:0567:5673:23b5]:222"),
					latency:  10 * time.Millisecond,
				},
			},
			want: netip.MustParseAddrPort("[2345:0425:2CA1:0000:0000:0567:5673:23b5]:222"),
		},
		{
			name:       "choose IPv6 address when latency is the same for v4 and v6",
			sendWGPing: true,
			ep: []endpointDetails{
				{
					addrPort: netip.MustParseAddrPort("1.1.1.1:111"),
					latency:  100 * time.Millisecond,
				},
				{
					addrPort: netip.MustParseAddrPort("[1::1]:567"),
					latency:  100 * time.Millisecond,
				},
			},
			want: netip.MustParseAddrPort("[1::1]:567"),
		},
	}

	for _, test := range wgTests {
		endpoint := &endpoint{
			isWireguardOnly: true,
			endpointState:   map[netip.AddrPort]*endpointState{},
			c: &Conn{
				noV4: atomic.Bool{},
				noV6: atomic.Bool{},
			},
		}

		for _, epd := range test.ep {
			endpoint.endpointState[epd.addrPort] = &endpointState{}
		}

		udpAddr, _, shouldPing := endpoint.addrForSendLocked(testTime)
		if !udpAddr.IsValid() {
			t.Error("udpAddr returned is not valid")
		}
		if shouldPing != test.sendWGPing {
			t.Errorf("addrForSendLocked did not indiciate correct ping state; got %v, want %v", shouldPing, test.sendWGPing)
		}

		for _, epd := range test.ep {
			state, ok := endpoint.endpointState[epd.addrPort]
			if !ok {
				t.Errorf("addr does not exist in endpoint state map")
			}

			latency, ok := state.latencyLocked()
			if ok {
				t.Errorf("latency was set for %v: %v", epd.addrPort, latency)
			}
			state.recentPongs = append(state.recentPongs, pongReply{
				latency: epd.latency,
			})
			state.recentPong = 0
		}

		udpAddr, _, shouldPing = endpoint.addrForSendLocked(testTime.Add(2 * time.Minute))
		if udpAddr != test.want {
			t.Errorf("udpAddr returned is not expected: got %v, want %v", udpAddr, test.want)
		}
		if shouldPing {
			t.Error("addrForSendLocked should not indicate ping is required")
		}
		if endpoint.bestAddr.AddrPort != test.want {
			t.Errorf("bestAddr.AddrPort is not as expected: got %v, want %v", endpoint.bestAddr.AddrPort, test.want)
		}
	}
}

// Copied from cmd/derper
func addWebSocketSupport(s *derp.Server, base http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := strings.ToLower(r.Header.Get("Upgrade"))

		// Very early versions of Tailscale set "Upgrade: WebSocket" but didn't actually
		// speak WebSockets (they still assumed DERP's binary framing). So to distinguish
		// clients that actually want WebSockets, look for an explicit "derp" subprotocol.
		if up != "websocket" || !strings.Contains(r.Header.Get("Sec-Websocket-Protocol"), "derp") {
			base.ServeHTTP(w, r)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:   []string{"derp"},
			OriginPatterns: []string{"*"},
			// Disable compression because we transmit WireGuard messages that
			// are not compressible.
			// Additionally, Safari has a broken implementation of compression
			// (see https://github.com/nhooyr/websocket/issues/218) that makes
			// enabling it actively harmful.
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			log.Printf("websocket.Accept: %v", err)
			return
		}
		defer c.Close(websocket.StatusInternalError, "closing")
		if c.Subprotocol() != "derp" {
			c.Close(websocket.StatusPolicyViolation, "client must speak the derp subprotocol")
			return
		}
		wc := websocket.NetConn(r.Context(), c, websocket.MessageBinary)
		brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
		s.Accept(r.Context(), wc, brw, r.RemoteAddr)
	})
}

func TestDERPForceWebsockets(t *testing.T) {
	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	// Create a DERP server manually, without a STUN server and with a custom
	// handler.
	derpServer := derp.NewServer(key.NewNode(), logf)
	derpHandler := derphttp.Handler(derpServer)
	derpHandler = addWebSocketSupport(derpServer, derpHandler)

	var upgradeCount int64
	httpsrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := r.Header.Get("Upgrade")
		if up != "" {
			if up != "websocket" {
				t.Errorf("unexpected upgrade header: %q", up)
			} else {
				atomic.AddInt64(&upgradeCount, 1)
			}
		}

		derpHandler.ServeHTTP(w, r)
	}))
	httpsrv.Config.ErrorLog = logger.StdLogger(logf)
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		derpServer.Close()
	})

	derpMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID:   1,
				RegionCode: "test",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:             "t1",
						RegionID:         1,
						HostName:         "test-node.unused",
						IPv4:             "127.0.0.1",
						IPv6:             "",
						STUNPort:         -1,
						DERPPort:         httpsrv.Listener.Addr().(*net.TCPAddr).Port,
						InsecureForTests: true,
					},
				},
			},
		},
	}

	m := &natlab.Machine{Name: "m1"}
	ms := newMagicStackFunc(t, logger.WithPrefix(logf, "conn1: "), m, derpMap, func(ms *Conn) {
		ms.SetDERPForceWebsockets(true)
	})
	defer ms.Close()

	if len(ms.conn.activeDerp) == 0 {
		t.Errorf("unexpected DERP empty got: %v want: >0", len(ms.conn.activeDerp))
	}

	if atomic.LoadInt64(&upgradeCount) == 0 {
		t.Errorf("no websocket upgrade requests seen")
	}
}

func TestBlockEndpoints(t *testing.T) {
	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	m := &natlab.Machine{Name: "m1"}
	ms := newMagicStackFunc(t, logger.WithPrefix(logf, "conn1: "), m, derpMap, nil)
	defer ms.Close()

	// Check that some endpoints exist. This should be the case as we should use
	// interface addresses as endpoints instantly on startup, and we already
	// have a DERP connection due to newMagicStackFunc.
	ms.conn.mu.Lock()
	haveEndpoint := false

	if len(ms.conn.lastEndpoints) > 0 {
		ep := ms.conn.lastEndpoints[0]
		if ep.Addr.Addr() == tailcfg.DerpMagicIPAddr {
			t.Fatal("DERP IP in endpoints list?", ep.Addr)
		}

		haveEndpoint = true
	}
	ms.conn.mu.Unlock()
	if !haveEndpoint {
		t.Fatal("no endpoints found")
	}

	// Block endpoints, should result in an update.
	ms.conn.SetBlockEndpoints(true)

	// Wait for endpoints to finish updating.
	waitForNoEndpoints(t, ms.conn)
}

func TestBlockEndpointsDERPOK(t *testing.T) {
	// This test is similar to TestBlockEndpoints, but it tests that we don't
	// mess up DERP somehow.

	mstun := &natlab.Machine{Name: "stun"}
	m1 := &natlab.Machine{Name: "m1"}
	m2 := &natlab.Machine{Name: "m2"}
	inet := natlab.NewInternet()
	sif := mstun.Attach("eth0", inet)
	m1if := m1.Attach("eth0", inet)
	m2if := m2.Attach("eth0", inet)

	d := &devices{
		m1:     m1,
		m1IP:   m1if.V4(),
		m2:     m2,
		m2IP:   m2if.V4(),
		stun:   mstun,
		stunIP: sif.V4(),
	}

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	derpMap, cleanupDerp := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanupDerp()

	ms1 := newMagicStack(t, logger.WithPrefix(logf, "conn1: "), d.m1, derpMap)
	defer ms1.Close()
	ms1.conn.SetDebugLoggingEnabled(true)
	ms2 := newMagicStack(t, logger.WithPrefix(logf, "conn2: "), d.m2, derpMap)
	defer ms2.Close()
	ms2.conn.SetDebugLoggingEnabled(true)

	cleanupMesh := meshStacks(logf, nil, ms1, ms2)
	defer cleanupMesh()

	m1IP := ms1.IP()
	m2IP := ms2.IP()
	logf("IPs: %s %s", m1IP, m2IP)

	cleanupPinger1 := newPinger(t, logf, ms1, ms2)
	defer cleanupPinger1()
	cleanupPinger2 := newPinger(t, logf, ms2, ms1)
	defer cleanupPinger2()

	// Wait for both peers to know about each other.
	for {
		if s1 := ms1.Status(); len(s1.Peer) != 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if s2 := ms2.Status(); len(s2.Peer) != 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}

	waitForEndpoints(t, ms1.conn)
	waitForEndpoints(t, ms2.conn)

	// SetBlockEndpoints is called later since it's incompatible with the test
	// meshStacks implementations.
	// We only set it on ms1, since ms2's endpoints should be ignored by ms1.
	ms1.conn.SetBlockEndpoints(true)

	// All endpoints should've been immediately removed from ms1.
	ep2, ok := ms1.conn.peerMap.endpointForNodeKey(ms2.Public())
	if !ok {
		t.Fatalf("endpoint not found for ms2 in ms1")
	}
	ep2.mu.Lock()
	if !ep2.blockEndpoints {
		t.Fatalf("endpoints not blocked on ep2 in ms1")
	}
	if len(ep2.endpointState) != 0 {
		ep2.mu.Unlock()
		t.Fatalf("endpoints not removed on ep2 in ms1")
	}
	ep2.mu.Unlock()

	// Wait for endpoints to finish updating.
	waitForNoEndpoints(t, ms1.conn)

	// Give time for another call-me-maybe packet to arrive. I couldn't think of
	// a better way than sleeping without making a bunch of changes.
	t.Logf("sleeping for call-me-maybe packet to be received and ignored")
	time.Sleep(time.Second)
	t.Logf("done sleeping")

	ep2.mu.Lock()
	defer ep2.mu.Unlock()
	for i := range ep2.endpointState {
		t.Fatalf("endpoint %q not missing", i.String())
	}
}

func getNonDERPEndpoints(ms *Conn) []tailcfg.Endpoint {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	nonDERPEndpoints := make([]tailcfg.Endpoint, 0, len(ms.lastEndpoints))
	for _, ep := range ms.lastEndpoints {
		if ep.Addr.Addr() != tailcfg.DerpMagicIPAddr {
			nonDERPEndpoints = append(nonDERPEndpoints, ep)
		}
	}
	return nonDERPEndpoints
}

func waitForNoEndpoints(t *testing.T, ms *Conn) {
	t.Helper()

	t.Log("waiting for endpoints to be blocked")
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		nonDERPEndpoints := getNonDERPEndpoints(ms)
		if len(nonDERPEndpoints) != 0 {
			t.Logf("some non-DERP endpoints were not blocked yet: %v", nonDERPEndpoints)
			continue
		}

		t.Log("endpoints are blocked")
		return
	}
	t.Fatal("endpoints were not blocked after 50 attempts")
}

func waitForEndpoints(t *testing.T, ms *Conn) {
	t.Helper()

	t.Log("waiting for endpoints to be found")
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		nonDERPEndpoints := getNonDERPEndpoints(ms)
		if len(nonDERPEndpoints) > 0 {
			t.Logf("non-DERP endpoints found: %v", nonDERPEndpoints)
			return
		}
	}
	t.Fatal("endpoint was not found after 50 attempts")
}
