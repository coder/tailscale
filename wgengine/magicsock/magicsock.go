// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"go4.org/mem"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/connstats"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/ping"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/sockstats"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/lazy"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
	"tailscale.com/util/ringbuffer"
	"tailscale.com/util/set"
	"tailscale.com/util/uniq"
	"tailscale.com/version"
	"tailscale.com/wgengine/capture"
)

const (
	// These are disco.Magic in big-endian form, 4 then 2 bytes. The
	// BPF filters need the magic in this format to match on it. Used
	// only in magicsock_linux.go, but defined here so that the test
	// which verifies this is the correct magic doesn't also need a
	// _linux variant.
	discoMagic1 = 0x5453f09f
	discoMagic2 = 0x92ac

	// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
	// is the max supported by a default configuration of macOS. Some platforms
	// will silently clamp the value.
	socketBufferSize = 7 << 20
)

// A Conn routes UDP packets and actively manages a list of its endpoints.
type Conn struct {
	// This block mirrors the contents and field order of the Options
	// struct. Initialized once at construction, then constant.

	logf                   logger.Logf
	epFunc                 func([]tailcfg.Endpoint)
	derpActiveFunc         func()
	idleFunc               func() time.Duration // nil means unknown
	testOnlyPacketListener nettype.PacketListener
	noteRecvActivity       func(key.NodePublic) // or nil, see Options.NoteRecvActivity
	netMon                 *netmon.Monitor      // or nil

	// ================================================================
	// No locking required to access these fields, either because
	// they're static after construction, or are wholly owned by a
	// single goroutine.

	connCtx       context.Context // closed on Conn.Close
	connCtxCancel func()          // closes connCtx
	donec         <-chan struct{} // connCtx.Done()'s to avoid context.cancelCtx.Done()'s mutex per call

	// pconn4 and pconn6 are the underlying UDP sockets used to
	// send/receive packets for wireguard and other magicsock
	// protocols.
	pconn4 RebindingUDPConn
	pconn6 RebindingUDPConn

	receiveBatchPool sync.Pool

	// closeDisco4 and closeDisco6 are io.Closers to shut down the raw
	// disco packet receivers. If nil, no raw disco receiver is
	// running for the given family.
	closeDisco4 io.Closer
	closeDisco6 io.Closer

	// netChecker is the prober that discovers local network
	// conditions, including the closest DERP relay and NAT mappings.
	netChecker *netcheck.Client

	// portMapper is the NAT-PMP/PCP/UPnP prober/client, for requesting
	// port mappings from NAT devices.
	portMapper *portmapper.Client

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc syncs.AtomicValue[func(p []byte, fromAddr netip.AddrPort)]

	// derpRecvCh is used by receiveDERP to read DERP messages.
	// It must have buffer size > 0; see issue 3736.
	derpRecvCh chan derpReadResult

	// bind is the wireguard-go conn.Bind for Conn.
	bind *connBind

	// ============================================================
	// Fields that must be accessed via atomic load/stores.

	// noV4 and noV6 are whether IPv4 and IPv6 are known to be
	// missing.  They're only used to suppress log spam. The name
	// is named negatively because in early start-up, we don't yet
	// necessarily have a netcheck.Report and don't want to skip
	// logging.
	noV4, noV6 atomic.Bool

	// noV4Send is whether IPv4 UDP is known to be unable to transmit
	// at all. This could happen if the socket is in an invalid state
	// (as can happen on darwin after a network link status change).
	noV4Send atomic.Bool

	// networkUp is whether the network is up (some interface is up
	// with IPv4 or IPv6). It's used to suppress log spam and prevent
	// new connection that'll fail.
	networkUp atomic.Bool

	// Whether debugging logging is enabled.
	debugLogging atomic.Bool

	// havePrivateKey is whether privateKey is non-zero.
	havePrivateKey  atomic.Bool
	publicKeyAtomic syncs.AtomicValue[key.NodePublic] // or NodeKey zero value if !havePrivateKey

	// derpMapAtomic is the same as derpMap, but without requiring
	// sync.Mutex. For use with NewRegionClient's callback, to avoid
	// lock ordering deadlocks. See issue 3726 and mu field docs.
	derpMapAtomic atomic.Pointer[tailcfg.DERPMap]

	lastNetCheckReport atomic.Pointer[netcheck.Report]

	// port is the preferred port from opts.Port; 0 means auto.
	port atomic.Uint32

	// headers that are passed to the DERP HTTP client
	derpHeader atomic.Pointer[http.Header]

	// whether websocket is always used by the DERP HTTP client
	derpForceWebsockets atomic.Bool

	// derpRegionDialer is passed to the DERP client
	derpRegionDialer atomic.Pointer[func(ctx context.Context, region *tailcfg.DERPRegion) net.Conn]

	// stats maintains per-connection counters.
	stats atomic.Pointer[connstats.Statistics]

	// captureHook, if non-nil, is the pcap logging callback when capturing.
	captureHook syncs.AtomicValue[capture.Callback]

	// discoPrivate is the private naclbox key used for active
	// discovery traffic. It is always present, and immutable.
	discoPrivate key.DiscoPrivate
	// public of discoPrivate. It is always present and immutable.
	discoPublic key.DiscoPublic
	// ShortString of discoPublic (to save logging work later). It is always
	// present and immutable.
	discoShort string

	// ============================================================
	// mu guards all following fields; see userspaceEngine lock
	// ordering rules against the engine. For derphttp, mu must
	// be held before derphttp.Client.mu.
	mu     sync.Mutex
	muCond *sync.Cond

	closed  bool        // Close was called
	closing atomic.Bool // Close is in progress (or done)

	// derpCleanupTimer is the timer that fires to occasionally clean
	// up idle DERP connections. It's only used when there is a non-home
	// DERP connection in use.
	derpCleanupTimer *time.Timer

	// derpCleanupTimerArmed is whether derpCleanupTimer is
	// scheduled to fire within derpCleanStaleInterval.
	derpCleanupTimerArmed bool

	// periodicReSTUNTimer, when non-nil, is an AfterFunc timer
	// that will call Conn.doPeriodicSTUN.
	periodicReSTUNTimer *time.Timer

	// blockEndpoints is whether to avoid capturing, storing and sending
	// endpoints gathered from local interfaces or STUN. Only DERP endpoints
	// will be sent.
	// This will also block incoming endpoints received via call-me-maybe disco
	// packets.
	blockEndpoints bool
	// endpointsUpdateActive indicates that updateEndpoints is
	// currently running. It's used to deduplicate concurrent endpoint
	// update requests.
	endpointsUpdateActive bool
	// wantEndpointsUpdate, if non-empty, means that a new endpoints
	// update should begin immediately after the currently-running one
	// completes. It can only be non-empty if
	// endpointsUpdateActive==true.
	wantEndpointsUpdate string // true if non-empty; string is reason
	// lastEndpoints records the endpoints found during the previous
	// endpoint discovery. It's used to avoid duplicate endpoint
	// change notifications.
	lastEndpoints []tailcfg.Endpoint

	// lastEndpointsTime is the last time the endpoints were updated,
	// even if there was no change.
	lastEndpointsTime time.Time

	// onEndpointRefreshed are funcs to run (in their own goroutines)
	// when endpoints are refreshed.
	onEndpointRefreshed map[*endpoint]func()

	// endpointTracker tracks the set of cached endpoints that we advertise
	// for a period of time before withdrawing them.
	endpointTracker endpointTracker

	// peerSet is the set of peers that are currently configured in
	// WireGuard. These are not used to filter inbound or outbound
	// traffic at all, but only to track what state can be cleaned up
	// in other maps below that are keyed by peer public key.
	peerSet map[key.NodePublic]struct{}

	// nodeOfDisco tracks the networkmap Node entity for each peer
	// discovery key.
	peerMap peerMap

	// discoInfo is the state for an active DiscoKey.
	discoInfo map[key.DiscoPublic]*discoInfo

	// netInfoFunc is a callback that provides a tailcfg.NetInfo when
	// discovered network conditions change.
	//
	// TODO(danderson): why can't it be set at construction time?
	// There seem to be a few natural places in ipn/local.go to
	// swallow untimely invocations.
	netInfoFunc func(*tailcfg.NetInfo) // nil until set
	// netInfoLast is the NetInfo provided in the last call to
	// netInfoFunc. It's used to deduplicate calls to netInfoFunc.
	//
	// TODO(danderson): should all the deduping happen in
	// ipn/local.go? We seem to be doing dedupe at several layers, and
	// magicsock could do with any complexity reduction it can get.
	netInfoLast *tailcfg.NetInfo

	derpMap     *tailcfg.DERPMap // nil (or zero regions/nodes) means DERP is disabled
	netMap      *netmap.NetworkMap
	privateKey  key.NodePrivate    // WireGuard private key for this node
	everHadKey  bool               // whether we ever had a non-zero private key
	myDerp      int                // nearest DERP region ID; 0 means none/unknown
	derpStarted chan struct{}      // closed on first connection to DERP; for tests & cleaner Close
	activeDerp  map[int]activeDerp // DERP regionID -> connection to a node in that region
	prevDerp    map[int]*syncs.WaitGroupChan

	// derpRoute contains optional alternate routes to use as an
	// optimization instead of contacting a peer via their home
	// DERP connection.  If they sent us a message on a different
	// DERP connection (which should really only be on our DERP
	// home connection, or what was once our home), then we
	// remember that route here to optimistically use instead of
	// creating a new DERP connection back to their home.
	derpRoute map[key.NodePublic]derpRoute

	// peerLastDerp tracks which DERP node we last used to speak with a
	// peer. It's only used to quiet logging, so we only log on change.
	peerLastDerp map[key.NodePublic]int

	// derpForcedWebsocketFunc is a callback that is called when a DERP
	// connection is forced to use WebSockets.
	derpForcedWebsocketFunc func(region int, reason string)

	// wgPinger is the WireGuard only pinger used for latency measurements.
	wgPinger lazy.SyncValue[*ping.Pinger]
}

// SetDebugLoggingEnabled controls whether spammy debug logging is enabled.
//
// Note that this is currently independent from the log levels, even though
// they're pretty correlated: debugging logs should be [v1] (or higher), but
// some non-debug logs may also still have a [vN] annotation. The [vN] level
// controls which gets shown in stderr. The dlogf method, on the other hand,
// controls which gets even printed or uploaded at any level.
func (c *Conn) SetDebugLoggingEnabled(v bool) {
	c.debugLogging.Store(v)
}

// dlogf logs a debug message if debug logging is enabled via SetDebugLoggingEnabled.
func (c *Conn) dlogf(format string, a ...any) {
	if c.debugLogging.Load() {
		c.logf(format, a...)
	}
}

// Options contains options for Listen.
type Options struct {
	// Logf optionally provides a log function to use.
	// Must not be nil.
	Logf logger.Logf

	// Port is the port to listen on.
	// Zero means to pick one automatically.
	Port uint16

	// EndpointsFunc optionally provides a func to be called when
	// endpoints change. The called func does not own the slice.
	EndpointsFunc func([]tailcfg.Endpoint)

	// BlockEndpoints is whether to avoid capturing, storing and sending
	// endpoints gathered from local interfaces or STUN. Only DERP endpoints
	// will be sent.
	// This does not disable the UDP socket or portmapping attempts as this
	// setting can be toggled at runtime.
	BlockEndpoints bool

	// DERPActiveFunc optionally provides a func to be called when
	// a connection is made to a DERP server.
	DERPActiveFunc func()

	// IdleFunc optionally provides a func to return how long
	// it's been since a TUN packet was sent or received.
	IdleFunc func() time.Duration

	// TestOnlyPacketListener optionally specifies how to create PacketConns.
	// Only used by tests.
	TestOnlyPacketListener nettype.PacketListener

	// NoteRecvActivity, if provided, is a func for magicsock to call
	// whenever it receives a packet from a a peer if it's been more
	// than ~10 seconds since the last one. (10 seconds is somewhat
	// arbitrary; the sole user just doesn't need or want it called on
	// every packet, just every minute or two for WireGuard timeouts,
	// and 10 seconds seems like a good trade-off between often enough
	// and not too often.)
	// The provided func is likely to call back into
	// Conn.ParseEndpoint, which acquires Conn.mu. As such, you should
	// not hold Conn.mu while calling it.
	NoteRecvActivity func(key.NodePublic)

	// NetMon is the network monitor to use.
	// With one, the portmapper won't be used.
	NetMon *netmon.Monitor
}

func (o *Options) logf() logger.Logf {
	if o.Logf == nil {
		panic("must provide magicsock.Options.logf")
	}
	return o.Logf
}

func (o *Options) endpointsFunc() func([]tailcfg.Endpoint) {
	if o == nil || o.EndpointsFunc == nil {
		return func([]tailcfg.Endpoint) {}
	}
	return o.EndpointsFunc
}

func (o *Options) derpActiveFunc() func() {
	if o == nil || o.DERPActiveFunc == nil {
		return func() {}
	}
	return o.DERPActiveFunc
}

// newConn is the error-free, network-listening-side-effect-free based
// of NewConn. Mostly for tests.
func newConn() *Conn {
	discoPrivate := key.NewDisco()
	c := &Conn{
		derpRecvCh:   make(chan derpReadResult, 1), // must be buffered, see issue 3736
		derpStarted:  make(chan struct{}),
		peerLastDerp: make(map[key.NodePublic]int),
		peerMap:      newPeerMap(),
		discoInfo:    make(map[key.DiscoPublic]*discoInfo),
		discoPrivate: discoPrivate,
		discoPublic:  discoPrivate.Public(),
	}
	c.discoShort = c.discoPublic.ShortString()
	c.bind = &connBind{Conn: c, closed: true}
	c.receiveBatchPool = sync.Pool{New: func() any {
		msgs := make([]ipv6.Message, c.bind.BatchSize())
		for i := range msgs {
			msgs[i].Buffers = make([][]byte, 1)
			msgs[i].OOB = make([]byte, controlMessageSize)
		}
		batch := &receiveBatch{
			msgs: msgs,
		}
		return batch
	}}
	c.muCond = sync.NewCond(&c.mu)
	c.networkUp.Store(true) // assume up until told otherwise
	return c
}

// NewConn creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
func NewConn(opts Options) (*Conn, error) {
	c := newConn()
	c.port.Store(uint32(opts.Port))
	c.logf = opts.logf()
	c.epFunc = opts.endpointsFunc()
	c.derpActiveFunc = opts.derpActiveFunc()
	c.blockEndpoints = opts.BlockEndpoints
	c.idleFunc = opts.IdleFunc
	c.testOnlyPacketListener = opts.TestOnlyPacketListener
	c.noteRecvActivity = opts.NoteRecvActivity
	c.portMapper = portmapper.NewClient(logger.WithPrefix(c.logf, "portmapper: "), opts.NetMon, nil, c.onPortMapChanged)
	if opts.NetMon != nil {
		c.portMapper.SetGatewayLookupFunc(opts.NetMon.GatewayAndSelfIP)
	}
	c.netMon = opts.NetMon

	if err := c.rebind(keepCurrentPort); err != nil {
		return nil, err
	}

	c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
	c.donec = c.connCtx.Done()
	c.netChecker = &netcheck.Client{
		Logf:                logger.WithPrefix(c.logf, "netcheck: "),
		NetMon:              c.netMon,
		GetSTUNConn4:        func() netcheck.STUNConn { return &c.pconn4 },
		GetSTUNConn6:        func() netcheck.STUNConn { return &c.pconn6 },
		SkipExternalNetwork: inTest(),
		PortMapper:          c.portMapper,
		UseDNSCache:         true,
		GetDERPHeaders: func() http.Header {
			h := c.derpHeader.Load()
			if h == nil {
				return nil
			}
			return h.Clone()
		},
	}

	c.ignoreSTUNPackets()

	if d4, err := c.listenRawDisco("ip4"); err == nil {
		c.logf("[v1] using BPF disco receiver for IPv4")
		c.closeDisco4 = d4
	} else {
		c.logf("[v1] couldn't create raw v4 disco listener, using regular listener instead: %v", err)
	}
	if d6, err := c.listenRawDisco("ip6"); err == nil {
		c.logf("[v1] using BPF disco receiver for IPv6")
		c.closeDisco6 = d6
	} else {
		c.logf("[v1] couldn't create raw v6 disco listener, using regular listener instead: %v", err)
	}

	c.logf("magicsock: disco key = %v", c.discoShort)
	return c, nil
}

// InstallCaptureHook installs a callback which is called to
// log debug information into the pcap stream. This function
// can be called with a nil argument to uninstall the capture
// hook.
func (c *Conn) InstallCaptureHook(cb capture.Callback) {
	c.captureHook.Store(cb)
}

// ignoreSTUNPackets sets a STUN packet processing func that does nothing.
func (c *Conn) ignoreSTUNPackets() {
	c.stunReceiveFunc.Store(func([]byte, netip.AddrPort) {})
}

// doPeriodicSTUN is called (in a new goroutine) by
// periodicReSTUNTimer when periodic STUNs are active.
func (c *Conn) doPeriodicSTUN() { c.ReSTUN("periodic") }

func (c *Conn) stopPeriodicReSTUNTimerLocked() {
	if t := c.periodicReSTUNTimer; t != nil {
		t.Stop()
		c.periodicReSTUNTimer = nil
	}
}

// c.mu must NOT be held.
func (c *Conn) updateEndpoints(why string) {
	metricUpdateEndpoints.Add(1)
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		why := c.wantEndpointsUpdate
		c.wantEndpointsUpdate = ""
		if !c.closed {
			if why != "" {
				go c.updateEndpoints(why)
				return
			}
			if c.shouldDoPeriodicReSTUNLocked() {
				// Pick a random duration between 20
				// and 26 seconds (just under 30s, a
				// common UDP NAT timeout on Linux,
				// etc)
				d := tstime.RandomDurationBetween(20*time.Second, 26*time.Second)
				if t := c.periodicReSTUNTimer; t != nil {
					if debugReSTUNStopOnIdle() {
						c.logf("resetting existing periodicSTUN to run in %v", d)
					}
					t.Reset(d)
				} else {
					if debugReSTUNStopOnIdle() {
						c.logf("scheduling periodicSTUN to run in %v", d)
					}
					c.periodicReSTUNTimer = time.AfterFunc(d, c.doPeriodicSTUN)
				}
			} else {
				if debugReSTUNStopOnIdle() {
					c.logf("periodic STUN idle")
				}
				c.stopPeriodicReSTUNTimerLocked()
			}
		}
		c.endpointsUpdateActive = false
		c.muCond.Broadcast()
	}()
	c.dlogf("[v1] magicsock: starting endpoint update (%s)", why)
	if c.noV4Send.Load() && c.shouldRebindOnFailedNetcheckV4Send() && runtime.GOOS != "js" {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if !closed {
			c.logf("magicsock: last netcheck reported send error. Rebinding.")
			c.Rebind()
		}
	}

	endpoints, err := c.determineEndpoints(c.connCtx)
	if err != nil {
		c.logf("magicsock: endpoint update (%s) failed: %v", why, err)
		// TODO(crawshaw): are there any conditions under which
		// we should trigger a retry based on the error here?
		return
	}

	if c.setEndpoints(endpoints) {
		c.logEndpointChange(endpoints)
		c.epFunc(endpoints)
	}
}

// c.mu must NOT be held.
func (c *Conn) shouldRebindOnFailedNetcheckV4Send() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.derpMap != nil && c.derpMap.HasSTUN() && !c.blockEndpoints
}

// setEndpoints records the new endpoints, reporting whether they're changed.
// It takes ownership of the slice.
func (c *Conn) setEndpoints(endpoints []tailcfg.Endpoint) (changed bool) {
	anySTUN := false
	for _, ep := range endpoints {
		if ep.Type == tailcfg.EndpointSTUN {
			anySTUN = true
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.blockEndpoints {
		anySTUN = false
		endpoints = []tailcfg.Endpoint{}
	}

	if !anySTUN && c.derpMap == nil && !inTest() {
		// Don't bother storing or reporting this yet. We
		// don't have a DERP map or any STUN entries, so we're
		// just starting up. A DERP map should arrive shortly
		// and then we'll have more interesting endpoints to
		// report. This saves a map update.
		// TODO(bradfitz): this optimization is currently
		// skipped during the e2e tests because they depend
		// too much on the exact sequence of updates.  Fix the
		// tests. But a protocol rewrite might happen first.
		c.dlogf("[v1] magicsock: ignoring pre-DERP map, STUN-less endpoint update: %v", endpoints)
		return false
	}

	c.lastEndpointsTime = time.Now()
	for de, fn := range c.onEndpointRefreshed {
		go fn()
		delete(c.onEndpointRefreshed, de)
	}

	if endpointSetsEqual(endpoints, c.lastEndpoints) {
		return false
	}
	c.lastEndpoints = endpoints
	return true
}

// setNetInfoHavePortMap updates NetInfo.HavePortMap to true.
func (c *Conn) setNetInfoHavePortMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.netInfoLast == nil {
		// No NetInfo yet. Nothing to update.
		return
	}
	if c.netInfoLast.HavePortMap {
		// No change.
		return
	}
	ni := c.netInfoLast.Clone()
	ni.HavePortMap = true
	c.callNetInfoCallbackLocked(ni)
}

func (c *Conn) updateNetInfo(ctx context.Context) (*netcheck.Report, error) {
	c.mu.Lock()
	dm := c.derpMap
	c.mu.Unlock()

	if dm == nil || c.networkDown() {
		return new(netcheck.Report), nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c.stunReceiveFunc.Store(c.netChecker.ReceiveSTUNPacket)
	defer c.ignoreSTUNPackets()

	report, err := c.netChecker.GetReport(ctx, dm)
	if err != nil {
		return nil, err
	}

	c.lastNetCheckReport.Store(report)
	c.noV4.Store(!report.IPv4)
	c.noV6.Store(!report.IPv6)
	c.noV4Send.Store(!report.IPv4CanSend)

	ni := &tailcfg.NetInfo{
		DERPLatency:           map[string]float64{},
		DERPLatencyV4:         map[int]float64{},
		DERPLatencyV6:         map[int]float64{},
		MappingVariesByDestIP: report.MappingVariesByDestIP,
		HairPinning:           report.HairPinning,
		UPnP:                  report.UPnP,
		PMP:                   report.PMP,
		PCP:                   report.PCP,
		HavePortMap:           c.portMapper.HaveMapping(),
		UDP:                   report.UDP,
		IPv6:                  report.IPv6,
		IPv4:                  report.IPv4,
		IPv4CanSend:           report.IPv4CanSend,
		ICMPv4:                report.ICMPv4,
		GlobalV4:              report.GlobalV4,
		GlobalV6:              report.GlobalV6,
	}
	for rid, d := range report.RegionV4Latency {
		ni.DERPLatencyV4[rid] = d.Seconds()
		ni.DERPLatency[fmt.Sprintf("%d-v4", rid)] = d.Seconds()
	}
	for rid, d := range report.RegionV6Latency {
		ni.DERPLatencyV6[rid] = d.Seconds()
		ni.DERPLatency[fmt.Sprintf("%d-v6", rid)] = d.Seconds()
	}

	ni.WorkingIPv6.Set(report.IPv6)
	ni.OSHasIPv6.Set(report.OSHasIPv6)
	ni.WorkingUDP.Set(report.UDP)
	ni.WorkingICMPv4.Set(report.ICMPv4)
	ni.PreferredDERP = report.PreferredDERP
	ni.CaptivePortal = report.CaptivePortal

	if ni.PreferredDERP == 0 {
		// Perhaps UDP is blocked. Pick a deterministic but arbitrary
		// one.
		ni.PreferredDERP = c.pickDERPFallback()
	}
	if !c.setNearestDERP(ni.PreferredDERP) {
		ni.PreferredDERP = 0
	}

	c.callNetInfoCallback(ni)
	return report, nil
}

// callNetInfoCallback calls the NetInfo callback (if previously
// registered with SetNetInfoCallback) if ni has substantially changed
// since the last state.
//
// callNetInfoCallback takes ownership of ni.
//
// c.mu must NOT be held.
func (c *Conn) callNetInfoCallback(ni *tailcfg.NetInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ni.BasicallyEqual(c.netInfoLast) {
		return
	}
	c.callNetInfoCallbackLocked(ni)
}

func (c *Conn) callNetInfoCallbackLocked(ni *tailcfg.NetInfo) {
	c.netInfoLast = ni
	if c.netInfoFunc != nil {
		c.dlogf("[v1] magicsock: netInfo update: %+v", ni)
		go c.netInfoFunc(ni)
	}
}

// addValidDiscoPathForTest makes addr a validated disco address for
// discoKey. It's used in tests to enable receiving of packets from
// addr without having to spin up the entire active discovery
// machinery.
func (c *Conn) addValidDiscoPathForTest(nodeKey key.NodePublic, addr netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.setNodeKeyForIPPort(addr, nodeKey)
}

func (c *Conn) SetNetInfoCallback(fn func(*tailcfg.NetInfo)) {
	if fn == nil {
		panic("nil NetInfoCallback")
	}
	c.mu.Lock()
	last := c.netInfoLast
	c.netInfoFunc = fn
	c.mu.Unlock()

	if last != nil {
		fn(last)
	}
}

// SetDERPForcedWebsocketCallback is called when a DERP connection
// switches to using WebSockets.
func (c *Conn) SetDERPForcedWebsocketCallback(fn func(region int, reason string)) {
	if fn == nil {
		panic("nil DERPClientForcedWebsocketCallback")
	}
	c.mu.Lock()
	c.derpForcedWebsocketFunc = fn
	for _, a := range c.activeDerp {
		a.c.SetForcedWebsocketCallback(fn)
	}
	c.mu.Unlock()
}

// LastRecvActivityOfNodeKey describes the time we last got traffic from
// this endpoint (updated every ~10 seconds).
func (c *Conn) LastRecvActivityOfNodeKey(nk key.NodePublic) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	de, ok := c.peerMap.endpointForNodeKey(nk)
	if !ok {
		return "never"
	}
	saw := de.lastRecv.LoadAtomic()
	if saw == 0 {
		return "never"
	}
	return mono.Since(saw).Round(time.Second).String()
}

// Ping handles a "tailscale ping" CLI query.
func (c *Conn) Ping(peer *tailcfg.Node, res *ipnstate.PingResult, cb func(*ipnstate.PingResult)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.privateKey.IsZero() {
		res.Err = "local tailscaled stopped"
		cb(res)
		return
	}
	if len(peer.Addresses) > 0 {
		res.NodeIP = peer.Addresses[0].Addr().String()
	}
	res.NodeName = peer.Name // prefer DNS name
	if res.NodeName == "" {
		res.NodeName = peer.Hostinfo.Hostname() // else hostname
	} else {
		res.NodeName, _, _ = strings.Cut(res.NodeName, ".")
	}

	ep, ok := c.peerMap.endpointForNodeKey(peer.Key)
	if !ok {
		res.Err = "unknown peer"
		cb(res)
		return
	}
	ep.cliPing(res, cb)
}

// c.mu must be held
func (c *Conn) populateCLIPingResponseLocked(res *ipnstate.PingResult, latency time.Duration, ep netip.AddrPort) {
	res.LatencySeconds = latency.Seconds()
	if ep.Addr() != tailcfg.DerpMagicIPAddr {
		res.Endpoint = ep.String()
		return
	}
	regionID := int(ep.Port())
	res.DERPRegionID = regionID
	res.DERPRegionCode = c.derpRegionCodeLocked(regionID)
}

// GetEndpointChanges returns the most recent changes for a particular
// endpoint. The returned EndpointChange structs are for debug use only and
// there are no guarantees about order, size, or content.
func (c *Conn) GetEndpointChanges(peer *tailcfg.Node) ([]EndpointChange, error) {
	c.mu.Lock()
	if c.privateKey.IsZero() {
		c.mu.Unlock()
		return nil, fmt.Errorf("tailscaled stopped")
	}
	ep, ok := c.peerMap.endpointForNodeKey(peer.Key)
	c.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown peer")
	}

	return ep.debugUpdates.GetAll(), nil
}

// DiscoPublicKey returns the discovery public key.
func (c *Conn) DiscoPublicKey() key.DiscoPublic {
	return c.discoPublic
}

// SetBlockEndpoints sets the blockEndpoints field. If enabled, all peer
// endpoints will be cleared from the peer map and every connection will
// immediately switch to DERP. Disabling endpoints does not affect the UDP
// socket or portmapper.
func (c *Conn) SetBlockEndpoints(block bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	didChange := c.blockEndpoints != block
	c.blockEndpoints = block
	if !didChange {
		return
	}

	// Re-gather local endpoints.
	const why = "SetBlockEndpoints"
	if c.endpointsUpdateActive {
		if c.wantEndpointsUpdate != why {
			c.dlogf("[v1] magicsock: SetBlockEndpoints: endpoint update active, need another later")
			c.wantEndpointsUpdate = why
		}
	} else {
		c.endpointsUpdateActive = true
		go c.updateEndpoints(why)
	}

	// Update all endpoints to abide by the new setting.
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.setBlockEndpoints(block)
	})
}

// determineEndpoints returns the machine's endpoint addresses. It
// does a STUN lookup (via netcheck) to determine its public address.
//
// c.mu must NOT be held.
func (c *Conn) determineEndpoints(ctx context.Context) ([]tailcfg.Endpoint, error) {
	var havePortmap bool
	var portmapExt netip.AddrPort
	if runtime.GOOS != "js" {
		portmapExt, havePortmap = c.portMapper.GetCachedMappingOrStartCreatingOne(ctx)
	}

	nr, err := c.updateNetInfo(ctx)
	if err != nil {
		c.logf("magicsock.Conn.determineEndpoints: updateNetInfo: %v", err)
		return nil, err
	}

	if runtime.GOOS == "js" {
		// TODO(bradfitz): why does control require an
		// endpoint? Otherwise it doesn't stream map responses
		// back.
		return []tailcfg.Endpoint{
			{
				Addr: netip.MustParseAddrPort("[fe80:123:456:789::1]:12345"),
				Type: tailcfg.EndpointLocal,
			},
		}, nil
	}

	var already map[netip.AddrPort]tailcfg.EndpointType // endpoint -> how it was found
	var eps []tailcfg.Endpoint                          // unique endpoints

	ipp := func(s string) (ipp netip.AddrPort) {
		ipp, _ = netip.ParseAddrPort(s)
		return
	}
	addAddr := func(ipp netip.AddrPort, et tailcfg.EndpointType) {
		if !ipp.IsValid() || (debugOmitLocalAddresses() && et == tailcfg.EndpointLocal) {
			return
		}
		if _, ok := already[ipp]; !ok {
			mak.Set(&already, ipp, et)
			eps = append(eps, tailcfg.Endpoint{Addr: ipp, Type: et})
		}
	}

	// If we didn't have a portmap earlier, maybe it's done by now.
	if !havePortmap {
		portmapExt, havePortmap = c.portMapper.GetCachedMappingOrStartCreatingOne(ctx)
	}
	if havePortmap {
		addAddr(portmapExt, tailcfg.EndpointPortmapped)
		c.setNetInfoHavePortMap()
	}

	if nr.GlobalV4 != "" {
		addAddr(ipp(nr.GlobalV4), tailcfg.EndpointSTUN)

		// If they're behind a hard NAT and are using a fixed
		// port locally, assume they might've added a static
		// port mapping on their router to the same explicit
		// port that tailscaled is running with. Worst case
		// it's an invalid candidate mapping.
		if port := c.port.Load(); nr.MappingVariesByDestIP.EqualBool(true) && port != 0 {
			if ip, _, err := net.SplitHostPort(nr.GlobalV4); err == nil {
				addAddr(ipp(net.JoinHostPort(ip, strconv.Itoa(int(port)))), tailcfg.EndpointSTUN4LocalPort)
			}
		}
	}
	if nr.GlobalV6 != "" {
		addAddr(ipp(nr.GlobalV6), tailcfg.EndpointSTUN)
	}

	c.ignoreSTUNPackets()

	// Update our set of endpoints by adding any endpoints that we
	// previously found but haven't expired yet. This also updates the
	// cache with the set of endpoints discovered in this function.
	//
	// NOTE: we do this here and not below so that we don't cache local
	// endpoints; we know that the local endpoints we discover are all
	// possible local endpoints since we determine them by looking at the
	// set of addresses on our local interfaces.
	//
	// TODO(andrew): If we pull in any cached endpoints, we should probably
	// do something to ensure we're propagating the removal of those cached
	// endpoints if they do actually time out without being rediscovered.
	// For now, though, rely on a minor LinkChange event causing this to
	// re-run.
	eps = c.endpointTracker.update(time.Now(), eps)

	if localAddr := c.pconn4.LocalAddr(); localAddr.IP.IsUnspecified() {
		ips, loopback, err := interfaces.LocalAddresses()
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 && len(eps) == 0 {
			// Only include loopback addresses if we have no
			// interfaces at all to use as endpoints and don't
			// have a public IPv4 or IPv6 address. This allows
			// for localhost testing when you're on a plane and
			// offline, for example.
			ips = loopback
		}
		for _, ip := range ips {
			addAddr(netip.AddrPortFrom(ip, uint16(localAddr.Port)), tailcfg.EndpointLocal)
		}
	} else {
		// Our local endpoint is bound to a particular address.
		// Do not offer addresses on other local interfaces.
		addAddr(ipp(localAddr.String()), tailcfg.EndpointLocal)
	}

	// Note: the endpoints are intentionally returned in priority order,
	// from "farthest but most reliable" to "closest but least
	// reliable." Addresses returned from STUN should be globally
	// addressable, but might go farther on the network than necessary.
	// Local interface addresses might have lower latency, but not be
	// globally addressable.
	//
	// The STUN address(es) are always first so that legacy wireguard
	// can use eps[0] as its only known endpoint address (although that's
	// obviously non-ideal).
	//
	// Despite this sorting, though, clients since 0.100 haven't relied
	// on the sorting order for any decisions.
	return eps, nil
}

// endpointSetsEqual reports whether x and y represent the same set of
// endpoints. The order doesn't matter.
//
// It does not mutate the slices.
func endpointSetsEqual(x, y []tailcfg.Endpoint) bool {
	if len(x) == len(y) {
		orderMatches := true
		for i := range x {
			if x[i] != y[i] {
				orderMatches = false
				break
			}
		}
		if orderMatches {
			return true
		}
	}
	m := map[tailcfg.Endpoint]int{}
	for _, v := range x {
		m[v] |= 1
	}
	for _, v := range y {
		m[v] |= 2
	}
	for _, n := range m {
		if n != 3 {
			return false
		}
	}
	return true
}

// LocalPort returns the current IPv4 listener's port number.
func (c *Conn) LocalPort() uint16 {
	if runtime.GOOS == "js" {
		return 12345
	}
	laddr := c.pconn4.LocalAddr()
	return uint16(laddr.Port)
}

var errNetworkDown = errors.New("magicsock: network down")

func (c *Conn) networkDown() bool { return !c.networkUp.Load() }

// Send implements conn.Bind.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.Send
func (c *Conn) Send(buffs [][]byte, ep conn.Endpoint) error {
	n := int64(len(buffs))
	metricSendData.Add(n)
	if c.networkDown() {
		metricSendDataNetworkDown.Add(n)
		return errNetworkDown
	}
	return ep.(*endpoint).send(buffs)
}

var errConnClosed = errors.New("Conn closed")

var errDropDerpPacket = errors.New("too many DERP packets queued; dropping")

var errNoUDP = errors.New("no UDP available on platform")

var (
	// This acts as a compile-time check for our usage of ipv6.Message in
	// batchingUDPConn for both IPv6 and IPv4 operations.
	_ ipv6.Message = ipv4.Message{}
)

func (c *Conn) sendUDPBatch(addr netip.AddrPort, buffs [][]byte) (sent bool, err error) {
	isIPv6 := false
	switch {
	case addr.Addr().Is4():
	case addr.Addr().Is6():
		isIPv6 = true
	default:
		panic("bogus sendUDPBatch addr type")
	}
	if isIPv6 {
		err = c.pconn6.WriteBatchTo(buffs, addr)
	} else {
		err = c.pconn4.WriteBatchTo(buffs, addr)
	}
	if err != nil {
		var errGSO neterror.ErrUDPGSODisabled
		if errors.As(err, &errGSO) {
			c.logf("magicsock: %s", errGSO.Error())
			err = errGSO.RetryErr
		}
	}
	return err == nil, err
}

// sendUDP sends UDP packet b to ipp.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDP(ipp netip.AddrPort, b []byte) (sent bool, err error) {
	if runtime.GOOS == "js" {
		return false, errNoUDP
	}
	sent, err = c.sendUDPStd(ipp, b)
	if err != nil {
		metricSendUDPError.Add(1)
	} else {
		if sent {
			metricSendUDP.Add(1)
		}
	}
	return
}

// sendUDP sends UDP packet b to addr.
// See sendAddr's docs on the return value meanings.
func (c *Conn) sendUDPStd(addr netip.AddrPort, b []byte) (sent bool, err error) {
	switch {
	case addr.Addr().Is4():
		_, err = c.pconn4.WriteToUDPAddrPort(b, addr)
		if err != nil && (c.noV4.Load() || neterror.TreatAsLostUDP(err)) {
			return false, nil
		}
	case addr.Addr().Is6():
		_, err = c.pconn6.WriteToUDPAddrPort(b, addr)
		if err != nil && (c.noV6.Load() || neterror.TreatAsLostUDP(err)) {
			return false, nil
		}
	default:
		panic("bogus sendUDPStd addr type")
	}
	return err == nil, err
}

// sendAddr sends packet b to addr, which is either a real UDP address
// or a fake UDP address representing a DERP server (see derpmap.go).
// The provided public key identifies the recipient.
//
// The returned err is whether there was an error writing when it
// should've worked.
// The returned sent is whether a packet went out at all.
// An example of when they might be different: sending to an
// IPv6 address when the local machine doesn't have IPv6 support
// returns (false, nil); it's not an error, but nothing was sent.
func (c *Conn) sendAddr(addr netip.AddrPort, pubKey key.NodePublic, b []byte) (sent bool, err error) {
	if addr.Addr() != tailcfg.DerpMagicIPAddr {
		return c.sendUDP(addr, b)
	}

	ch := c.derpWriteChanOfAddr(addr, pubKey)
	if ch == nil {
		metricSendDERPErrorChan.Add(1)
		return false, nil
	}

	// TODO(bradfitz): this makes garbage for now; we could use a
	// buffer pool later.  Previously we passed ownership of this
	// to derpWriteRequest and waited for derphttp.Client.Send to
	// complete, but that's too slow while holding wireguard-go
	// internal locks.
	pkt := make([]byte, len(b))
	copy(pkt, b)

	select {
	case <-c.donec:
		metricSendDERPErrorClosed.Add(1)
		return false, errConnClosed
	case ch <- derpWriteRequest{addr, pubKey, pkt}:
		metricSendDERPQueued.Add(1)
		return true, nil
	default:
		metricSendDERPErrorQueue.Add(1)
		// Too many writes queued. Drop packet.
		return false, errDropDerpPacket
	}
}

type receiveBatch struct {
	msgs []ipv6.Message
}

func (c *Conn) getReceiveBatchForBuffs(buffs [][]byte) *receiveBatch {
	batch := c.receiveBatchPool.Get().(*receiveBatch)
	for i := range buffs {
		batch.msgs[i].Buffers[0] = buffs[i]
		batch.msgs[i].OOB = batch.msgs[i].OOB[:cap(batch.msgs[i].OOB)]
	}
	return batch
}

func (c *Conn) putReceiveBatch(batch *receiveBatch) {
	for i := range batch.msgs {
		batch.msgs[i] = ipv6.Message{Buffers: batch.msgs[i].Buffers, OOB: batch.msgs[i].OOB}
	}
	c.receiveBatchPool.Put(batch)
}

// receiveIPv4 creates an IPv4 ReceiveFunc reading from c.pconn4.
func (c *Conn) receiveIPv4() conn.ReceiveFunc {
	return c.mkReceiveFunc(&c.pconn4, &health.ReceiveIPv4, metricRecvDataIPv4)
}

// receiveIPv6 creates an IPv6 ReceiveFunc reading from c.pconn6.
func (c *Conn) receiveIPv6() conn.ReceiveFunc {
	return c.mkReceiveFunc(&c.pconn6, &health.ReceiveIPv6, metricRecvDataIPv6)
}

// mkReceiveFunc creates a ReceiveFunc reading from ruc.
// The provided healthItem and metric are updated if non-nil.
func (c *Conn) mkReceiveFunc(ruc *RebindingUDPConn, healthItem *health.ReceiveFuncStats, metric *clientmetric.Metric) conn.ReceiveFunc {
	// epCache caches an IPPort->endpoint for hot flows.
	var epCache ippEndpointCache

	return func(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if healthItem != nil {
			healthItem.Enter()
			defer healthItem.Exit()
		}
		if ruc == nil {
			panic("nil RebindingUDPConn")
		}

		batch := c.getReceiveBatchForBuffs(buffs)
		defer c.putReceiveBatch(batch)
		for {
			numMsgs, err := ruc.ReadBatch(batch.msgs[:len(buffs)], 0)
			if err != nil {
				if neterror.PacketWasTruncated(err) {
					continue
				}
				return 0, err
			}

			reportToCaller := false
			for i, msg := range batch.msgs[:numMsgs] {
				if msg.N == 0 {
					sizes[i] = 0
					continue
				}
				ipp := msg.Addr.(*net.UDPAddr).AddrPort()
				if ep, ok := c.receiveIP(msg.Buffers[0][:msg.N], ipp, &epCache); ok {
					if metric != nil {
						metric.Add(1)
					}
					eps[i] = ep
					sizes[i] = msg.N
					reportToCaller = true
				} else {
					sizes[i] = 0
				}
			}
			if reportToCaller {
				return numMsgs, nil
			}
		}
	}
}

// receiveIP is the shared bits of ReceiveIPv4 and ReceiveIPv6.
//
// ok is whether this read should be reported up to wireguard-go (our
// caller).
func (c *Conn) receiveIP(b []byte, ipp netip.AddrPort, cache *ippEndpointCache) (ep *endpoint, ok bool) {
	if stun.Is(b) {
		c.stunReceiveFunc.Load()(b, ipp)
		return nil, false
	}
	if c.handleDiscoMessage(b, ipp, key.NodePublic{}, discoRXPathUDP) {
		return nil, false
	}
	if !c.havePrivateKey.Load() {
		// If we have no private key, we're logged out or
		// stopped. Don't try to pass these wireguard packets
		// up to wireguard-go; it'll just complain (issue 1167).
		return nil, false
	}
	if cache.ipp == ipp && cache.de != nil && cache.gen == cache.de.numStopAndReset() {
		ep = cache.de
	} else {
		c.mu.Lock()
		de, ok := c.peerMap.endpointForIPPort(ipp)
		c.mu.Unlock()
		if !ok {
			return nil, false
		}
		cache.ipp = ipp
		cache.de = de
		cache.gen = de.numStopAndReset()
		ep = de
	}
	ep.noteRecvActivity()
	if stats := c.stats.Load(); stats != nil {
		stats.UpdateRxPhysical(ep.nodeAddr, ipp, len(b))
	}
	return ep, true
}

// discoLogLevel controls the verbosity of discovery log messages.
type discoLogLevel int

const (
	// discoLog means that a message should be logged.
	discoLog discoLogLevel = iota

	// discoVerboseLog means that a message should only be logged
	// in TS_DEBUG_DISCO mode.
	discoVerboseLog
)

// TS_DISCO_PONG_IPV4_DELAY, if set, is a time.Duration string that is how much
// fake latency to add before replying to disco pings. This can be used to bias
// peers towards using IPv6 when both IPv4 and IPv6 are available at similar
// speeds.
var debugIPv4DiscoPingPenalty = envknob.RegisterDuration("TS_DISCO_PONG_IPV4_DELAY")

// sendDiscoMessage sends discovery message m to dstDisco at dst.
//
// If dst is a DERP IP:port, then dstKey must be non-zero.
//
// The dstKey should only be non-zero if the dstDisco key
// unambiguously maps to exactly one peer.
func (c *Conn) sendDiscoMessage(dst netip.AddrPort, dstKey key.NodePublic, dstDisco key.DiscoPublic, m disco.Message, logLevel discoLogLevel) (sent bool, err error) {
	isDERP := dst.Addr() == tailcfg.DerpMagicIPAddr
	if _, isPong := m.(*disco.Pong); isPong && !isDERP && dst.Addr().Is4() {
		time.Sleep(debugIPv4DiscoPingPenalty())
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false, errConnClosed
	}
	pkt := make([]byte, 0, 512) // TODO: size it correctly? pool? if it matters.
	pkt = append(pkt, disco.Magic...)
	pkt = c.discoPublic.AppendTo(pkt)
	di := c.discoInfoLocked(dstDisco)
	c.mu.Unlock()

	if isDERP {
		metricSendDiscoDERP.Add(1)
	} else {
		metricSendDiscoUDP.Add(1)
	}

	box := di.sharedKey.Seal(m.AppendMarshal(nil))
	pkt = append(pkt, box...)
	sent, err = c.sendAddr(dst, dstKey, pkt)
	if sent {
		if logLevel == discoLog || (logLevel == discoVerboseLog && debugDisco()) {
			node := "?"
			if !dstKey.IsZero() {
				node = dstKey.ShortString()
			}
			c.dlogf("[v1] magicsock: disco: %v->%v (%v, %v) sent %v", c.discoShort, dstDisco.ShortString(), node, derpStr(dst.String()), disco.MessageSummary(m))
		}
		if isDERP {
			metricSentDiscoDERP.Add(1)
		} else {
			metricSentDiscoUDP.Add(1)
		}
		switch m.(type) {
		case *disco.Ping:
			metricSentDiscoPing.Add(1)
		case *disco.Pong:
			metricSentDiscoPong.Add(1)
		case *disco.CallMeMaybe:
			metricSentDiscoCallMeMaybe.Add(1)
		}
	} else if err == nil {
		// Can't send. (e.g. no IPv6 locally)
	} else {
		if !c.networkDown() {
			c.logf("magicsock: disco: failed to send %T to %v: %v", m, dst, err)
		}
	}
	return sent, err
}

type discoRXPath string

const (
	discoRXPathUDP       discoRXPath = "UDP socket"
	discoRXPathDERP      discoRXPath = "DERP"
	discoRXPathRawSocket discoRXPath = "raw socket"
)

// handleDiscoMessage handles a discovery message and reports whether
// msg was a Tailscale inter-node discovery message.
//
// A discovery message has the form:
//
//   - magic             [6]byte
//   - senderDiscoPubKey [32]byte
//   - nonce             [24]byte
//   - naclbox of payload (see tailscale.com/disco package for inner payload format)
//
// For messages received over DERP, the src.Addr() will be derpMagicIP (with
// src.Port() being the region ID) and the derpNodeSrc will be the node key
// it was received from at the DERP layer. derpNodeSrc is zero when received
// over UDP.
func (c *Conn) handleDiscoMessage(msg []byte, src netip.AddrPort, derpNodeSrc key.NodePublic, via discoRXPath) (isDiscoMsg bool) {
	const headerLen = len(disco.Magic) + key.DiscoPublicRawLen
	if len(msg) < headerLen || string(msg[:len(disco.Magic)]) != disco.Magic {
		return false
	}

	// If the first four parts are the prefix of disco.Magic
	// (0x5453f09f) then it's definitely not a valid WireGuard
	// packet (which starts with little-endian uint32 1, 2, 3, 4).
	// Use naked returns for all following paths.
	isDiscoMsg = true

	sender := key.DiscoPublicFromRaw32(mem.B(msg[len(disco.Magic):headerLen]))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	if debugDisco() {
		c.logf("magicsock: disco: got disco-looking frame from %v via %s", sender.ShortString(), via)
	}
	if c.privateKey.IsZero() {
		// Ignore disco messages when we're stopped.
		// Still return true, to not pass it down to wireguard.
		return
	}

	isDERP := src.Addr() == tailcfg.DerpMagicIPAddr
	if !isDERP && c.blockEndpoints {
		// Ignore disco messages over UDP if endpoints are blocked.
		return
	}

	if !c.peerMap.anyEndpointForDiscoKey(sender) {
		metricRecvDiscoBadPeer.Add(1)
		if debugDisco() {
			c.logf("magicsock: disco: ignoring disco-looking frame, don't know endpoint for %v", sender.ShortString())
		}
		return
	}

	// We're now reasonably sure we're expecting communication from
	// this peer, do the heavy crypto lifting to see what they want.
	//
	// From here on, peerNode and de are non-nil.

	di := c.discoInfoLocked(sender)

	sealedBox := msg[headerLen:]
	payload, ok := di.sharedKey.Open(sealedBox)
	if !ok {
		// This might be have been intended for a previous
		// disco key.  When we restart we get a new disco key
		// and old packets might've still been in flight (or
		// scheduled). This is particularly the case for LANs
		// or non-NATed endpoints. UDP offloading on Linux
		// can also cause this when a disco message is
		// received via raw socket at the head of a coalesced
		// group of messages. Don't log in normal case.
		// Callers may choose to pass on to wireguard, in case
		// it's actually a wireguard packet (super unlikely, but).
		if debugDisco() {
			c.logf("magicsock: disco: failed to open naclbox from %v (wrong rcpt?) via %s", sender, via)
		}
		metricRecvDiscoBadKey.Add(1)
		return
	}

	// Emit information about the disco frame into the pcap stream
	// if a capture hook is installed.
	if cb := c.captureHook.Load(); cb != nil {
		cb(capture.PathDisco, time.Now(), disco.ToPCAPFrame(src, derpNodeSrc, payload), packet.CaptureMeta{})
	}

	dm, err := disco.Parse(payload)
	if debugDisco() {
		c.logf("magicsock: disco: disco.Parse = %T, %v", dm, err)
	}
	if err != nil {
		// Couldn't parse it, but it was inside a correctly
		// signed box, so just ignore it, assuming it's from a
		// newer version of Tailscale that we don't
		// understand. Not even worth logging about, lest it
		// be too spammy for old clients.
		metricRecvDiscoBadParse.Add(1)
		return
	}

	if isDERP {
		metricRecvDiscoDERP.Add(1)
	} else {
		metricRecvDiscoUDP.Add(1)
	}

	switch dm := dm.(type) {
	case *disco.Ping:
		metricRecvDiscoPing.Add(1)
		c.handlePingLocked(dm, src, di, derpNodeSrc)
	case *disco.Pong:
		metricRecvDiscoPong.Add(1)
		// There might be multiple nodes for the sender's DiscoKey.
		// Ask each to handle it, stopping once one reports that
		// the Pong's TxID was theirs.
		c.peerMap.forEachEndpointWithDiscoKey(sender, func(ep *endpoint) (keepGoing bool) {
			if ep.handlePongConnLocked(dm, di, src) {
				return false
			}
			return true
		})
	case *disco.CallMeMaybe:
		metricRecvDiscoCallMeMaybe.Add(1)
		if !isDERP || derpNodeSrc.IsZero() {
			// CallMeMaybe messages should only come via DERP.
			c.logf("[unexpected] CallMeMaybe packets should only come via DERP")
			return
		}
		nodeKey := derpNodeSrc
		ep, ok := c.peerMap.endpointForNodeKey(nodeKey)
		if !ok {
			metricRecvDiscoCallMeMaybeBadNode.Add(1)
			c.logf("magicsock: disco: ignoring CallMeMaybe from %v; %v is unknown", sender.ShortString(), derpNodeSrc.ShortString())
			return
		}
		epDisco := ep.disco.Load()
		if epDisco == nil {
			return
		}
		if epDisco.key != di.discoKey {
			metricRecvDiscoCallMeMaybeBadDisco.Add(1)
			c.logf("[unexpected] CallMeMaybe from peer via DERP whose netmap discokey != disco source")
			return
		}
		if c.blockEndpoints {
			c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v) got call-me-maybe with %d endpoints, but endpoints blocked",
				c.discoShort, epDisco.short,
				ep.publicKey.ShortString(), derpStr(src.String()),
				len(dm.MyNumber),
			)
			return
		}
		c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v) got call-me-maybe, %d endpoints",
			c.discoShort, epDisco.short,
			ep.publicKey.ShortString(), derpStr(src.String()),
			len(dm.MyNumber))
		go ep.handleCallMeMaybe(dm)
	}
	return
}

// unambiguousNodeKeyOfPingLocked attempts to look up an unambiguous mapping
// from a DiscoKey dk (which sent ping dm) to a NodeKey. ok is true
// if there's the NodeKey is known unambiguously.
//
// derpNodeSrc is non-zero if the disco ping arrived via DERP.
//
// c.mu must be held.
func (c *Conn) unambiguousNodeKeyOfPingLocked(dm *disco.Ping, dk key.DiscoPublic, derpNodeSrc key.NodePublic) (nk key.NodePublic, ok bool) {
	if !derpNodeSrc.IsZero() {
		if ep, ok := c.peerMap.endpointForNodeKey(derpNodeSrc); ok {
			epDisco := ep.disco.Load()
			if epDisco != nil && epDisco.key == dk {
				return derpNodeSrc, true
			}
		}
	}

	// Pings after 1.16.0 contains its node source. See if it maps back.
	if !dm.NodeKey.IsZero() {
		if ep, ok := c.peerMap.endpointForNodeKey(dm.NodeKey); ok {
			epDisco := ep.disco.Load()
			if epDisco != nil && epDisco.key == dk {
				return dm.NodeKey, true
			}
		}
	}

	// If there's exactly 1 node in our netmap with DiscoKey dk,
	// then it's not ambiguous which node key dm was from.
	if set := c.peerMap.nodesOfDisco[dk]; len(set) == 1 {
		for nk = range set {
			return nk, true
		}
	}

	return nk, false
}

// di is the discoInfo of the source of the ping.
// derpNodeSrc is non-zero if the ping arrived via DERP.
func (c *Conn) handlePingLocked(dm *disco.Ping, src netip.AddrPort, di *discoInfo, derpNodeSrc key.NodePublic) {
	likelyHeartBeat := src == di.lastPingFrom && time.Since(di.lastPingTime) < 5*time.Second
	di.lastPingFrom = src
	di.lastPingTime = time.Now()
	isDerp := src.Addr() == tailcfg.DerpMagicIPAddr

	// If we can figure out with certainty which node key this disco
	// message is for, eagerly update our IP<>node and disco<>node
	// mappings to make p2p path discovery faster in simple
	// cases. Without this, disco would still work, but would be
	// reliant on DERP call-me-maybe to establish the disco<>node
	// mapping, and on subsequent disco handlePongLocked to establish
	// the IP<>disco mapping.
	if nk, ok := c.unambiguousNodeKeyOfPingLocked(dm, di.discoKey, derpNodeSrc); ok {
		if !isDerp {
			c.peerMap.setNodeKeyForIPPort(src, nk)
		}
	}

	// If we got a ping over DERP, then derpNodeSrc is non-zero and we reply
	// over DERP (in which case ipDst is also a DERP address).
	// But if the ping was over UDP (ipDst is not a DERP address), then dstKey
	// will be zero here, but that's fine: sendDiscoMessage only requires
	// a dstKey if the dst ip:port is DERP.
	dstKey := derpNodeSrc

	// Remember this route if not present.
	var numNodes int
	var dup bool
	if isDerp {
		if ep, ok := c.peerMap.endpointForNodeKey(derpNodeSrc); ok {
			if ep.addCandidateEndpoint(src, dm.TxID) {
				return
			}
			numNodes = 1
		}
	} else {
		c.peerMap.forEachEndpointWithDiscoKey(di.discoKey, func(ep *endpoint) (keepGoing bool) {
			if ep.addCandidateEndpoint(src, dm.TxID) {
				dup = true
				return false
			}
			numNodes++
			if numNodes == 1 && dstKey.IsZero() {
				dstKey = ep.publicKey
			}
			return true
		})
		if dup {
			return
		}
		if numNodes > 1 {
			// Zero it out if it's ambiguous, so sendDiscoMessage logging
			// isn't confusing.
			dstKey = key.NodePublic{}
		}
	}

	if numNodes == 0 {
		c.logf("[unexpected] got disco ping from %v/%v for node not in peers", src, derpNodeSrc)
		return
	}

	if !likelyHeartBeat || debugDisco() {
		pingNodeSrcStr := dstKey.ShortString()
		if numNodes > 1 {
			pingNodeSrcStr = "[one-of-multi]"
		}
		c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got ping tx=%x", c.discoShort, di.discoShort, pingNodeSrcStr, src, dm.TxID[:6])
	}

	ipDst := src
	discoDest := di.discoKey
	go c.sendDiscoMessage(ipDst, dstKey, discoDest, &disco.Pong{
		TxID: dm.TxID,
		Src:  src,
	}, discoVerboseLog)
}

// enqueueCallMeMaybe schedules a send of disco.CallMeMaybe to de via derpAddr
// once we know that our STUN endpoint is fresh.
//
// derpAddr is de.derpAddr at the time of send. It's assumed the peer won't be
// flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
// If they do, traffic will just go over DERP for a bit longer until the next
// discovery round.
func (c *Conn) enqueueCallMeMaybe(derpAddr netip.AddrPort, de *endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()

	epDisco := de.disco.Load()
	if epDisco == nil {
		return
	}

	if !c.lastEndpointsTime.After(time.Now().Add(-endpointsFreshEnoughDuration)) {
		c.dlogf("[v1] magicsock: want call-me-maybe but endpoints stale; restunning")

		mak.Set(&c.onEndpointRefreshed, de, func() {
			c.dlogf("[v1] magicsock: STUN done; sending call-me-maybe to %v %v", epDisco.short, de.publicKey.ShortString())
			c.enqueueCallMeMaybe(derpAddr, de)
		})
		// TODO(bradfitz): make a new 'reSTUNQuickly' method
		// that passes down a do-a-lite-netcheck flag down to
		// netcheck that does 1 (or 2 max) STUN queries
		// (UDP-only, not HTTPs) to find our port mapping to
		// our home DERP and maybe one other. For now we do a
		// "full" ReSTUN which may or may not be a full one
		// (depending on age) and may do HTTPS timing queries
		// (if UDP is blocked). Good enough for now.
		go c.ReSTUN("refresh-for-peering")
		return
	}

	eps := make([]netip.AddrPort, 0, len(c.lastEndpoints))
	for _, ep := range c.lastEndpoints {
		eps = append(eps, ep.Addr)
	}
	// NOTE: sending an empty call-me-maybe (e.g. when BlockEndpoints is true)
	// is still valid and results in the other side forgetting all the endpoints
	// it knows of ours.
	go de.c.sendDiscoMessage(derpAddr, de.publicKey, epDisco.key, &disco.CallMeMaybe{MyNumber: eps}, discoLog)
	if debugSendCallMeUnknownPeer() {
		// Send a callMeMaybe packet to a non-existent peer
		unknownKey := key.NewNode().Public()
		c.logf("magicsock: sending CallMeMaybe to unknown peer per TS_DEBUG_SEND_CALLME_UNKNOWN_PEER")
		go de.c.sendDiscoMessage(derpAddr, unknownKey, epDisco.key, &disco.CallMeMaybe{MyNumber: eps}, discoLog)
	}
}

// discoInfoLocked returns the previous or new discoInfo for k.
//
// c.mu must be held.
func (c *Conn) discoInfoLocked(k key.DiscoPublic) *discoInfo {
	di, ok := c.discoInfo[k]
	if !ok {
		di = &discoInfo{
			discoKey:   k,
			discoShort: k.ShortString(),
			sharedKey:  c.discoPrivate.Shared(k),
		}
		c.discoInfo[k] = di
	}
	return di
}

func (c *Conn) SetDERPHeader(header http.Header) {
	c.derpHeader.Store(&header)
}

func (c *Conn) SetDERPForceWebsockets(v bool) {
	c.derpForceWebsockets.Store(v)
}

func (c *Conn) SetDERPRegionDialer(dialer func(ctx context.Context, region *tailcfg.DERPRegion) net.Conn) {
	c.derpRegionDialer.Store(&dialer)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.activeDerp {
		d.c.SetRegionDialer(dialer)
	}
}

func (c *Conn) SetNetworkUp(up bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.networkUp.Load() == up {
		return
	}

	c.logf("magicsock: SetNetworkUp(%v)", up)
	c.networkUp.Store(up)

	if up {
		c.startDerpHomeConnectLocked()
	} else {
		c.portMapper.NoteNetworkDown()
		c.closeAllDerpLocked("network-down")
	}
}

// SetPreferredPort sets the connection's preferred local port.
func (c *Conn) SetPreferredPort(port uint16) {
	if uint16(c.port.Load()) == port {
		return
	}
	c.port.Store(uint32(port))

	if err := c.rebind(dropCurrentPort); err != nil {
		c.logf("%w", err)
		return
	}
	c.resetEndpointStates()
}

// SetPrivateKey sets the connection's private key.
//
// This is only used to be able prove our identity when connecting to
// DERP servers.
//
// If the private key changes, any DERP connections are torn down &
// recreated when needed.
func (c *Conn) SetPrivateKey(privateKey key.NodePrivate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldKey, newKey := c.privateKey, privateKey
	if newKey.Equal(oldKey) {
		return nil
	}
	c.privateKey = newKey
	c.havePrivateKey.Store(!newKey.IsZero())

	if newKey.IsZero() {
		c.publicKeyAtomic.Store(key.NodePublic{})
	} else {
		c.publicKeyAtomic.Store(newKey.Public())
	}

	if oldKey.IsZero() {
		c.everHadKey = true
		c.logf("magicsock: SetPrivateKey called (init)")
		go c.ReSTUN("set-private-key")
	} else if newKey.IsZero() {
		c.logf("magicsock: SetPrivateKey called (zeroed)")
		c.closeAllDerpLocked("zero-private-key")
		c.stopPeriodicReSTUNTimerLocked()
		c.onEndpointRefreshed = nil
	} else {
		c.logf("magicsock: SetPrivateKey called (changed)")
		c.closeAllDerpLocked("new-private-key")
	}

	// Key changed. Close existing DERP connections and reconnect to home.
	if c.myDerp != 0 && !newKey.IsZero() {
		c.logf("magicsock: private key changed, reconnecting to home derp-%d", c.myDerp)
		c.startDerpHomeConnectLocked()
	}

	if newKey.IsZero() {
		c.peerMap.forEachEndpoint(func(ep *endpoint) {
			ep.stopAndReset()
		})
	}

	return nil
}

// UpdatePeers is called when the set of WireGuard peers changes. It
// then removes any state for old peers.
//
// The caller passes ownership of newPeers map to UpdatePeers.
func (c *Conn) UpdatePeers(newPeers map[key.NodePublic]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldPeers := c.peerSet
	c.peerSet = newPeers

	// Clean up any key.NodePublic-keyed maps for peers that no longer
	// exist.
	for peer := range oldPeers {
		if _, ok := newPeers[peer]; !ok {
			delete(c.derpRoute, peer)
			delete(c.peerLastDerp, peer)
		}
	}

	if len(oldPeers) == 0 && len(newPeers) > 0 {
		go c.ReSTUN("non-zero-peers")
	}
}

func nodesEqual(x, y []*tailcfg.Node) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if !x[i].Equal(y[i]) {
			return false
		}
	}
	return true
}

// SetNetworkMap is called when the control client gets a new network
// map from the control server. It must always be non-nil.
//
// It should not use the DERPMap field of NetworkMap; that's
// conditionally sent to SetDERPMap instead.
func (c *Conn) SetNetworkMap(nm *netmap.NetworkMap) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	priorNetmap := c.netMap
	var priorDebug *tailcfg.Debug
	if priorNetmap != nil {
		priorDebug = priorNetmap.Debug
	}
	debugChanged := !reflect.DeepEqual(priorDebug, nm.Debug)
	metricNumPeers.Set(int64(len(nm.Peers)))

	// Update c.netMap regardless, before the following early return.
	c.netMap = nm

	if priorNetmap != nil && nodesEqual(priorNetmap.Peers, nm.Peers) && !debugChanged {
		// The rest of this function is all adjusting state for peers that have
		// changed. But if the set of peers is equal and the debug flags (for
		// silent disco) haven't changed, no need to do anything else.
		return
	}

	c.logf("[v1] magicsock: got updated network map; %d peers", len(nm.Peers))
	heartbeatDisabled := debugEnableSilentDisco() || (c.netMap != nil && c.netMap.Debug != nil && c.netMap.Debug.EnableSilentDisco)

	// Set a maximum size for our set of endpoint ring buffers by assuming
	// that a single large update is ~500 bytes, and that we want to not
	// use more than 1MiB of memory on phones / 4MiB on other devices.
	// Calculate the per-endpoint ring buffer size by dividing that out,
	// but always storing at least two entries.
	var entriesPerBuffer int = 2
	if len(nm.Peers) > 0 {
		var maxRingBufferSize int
		if runtime.GOOS == "ios" || runtime.GOOS == "android" {
			maxRingBufferSize = 1 * 1024 * 1024
		} else {
			maxRingBufferSize = 4 * 1024 * 1024
		}
		if v := debugRingBufferMaxSizeBytes(); v > 0 {
			maxRingBufferSize = v
		}

		const averageRingBufferElemSize = 512
		entriesPerBuffer = maxRingBufferSize / (averageRingBufferElemSize * len(nm.Peers))
		if entriesPerBuffer < 2 {
			entriesPerBuffer = 2
		}
	}

	// Try a pass of just upserting nodes and creating missing
	// endpoints. If the set of nodes is the same, this is an
	// efficient alloc-free update. If the set of nodes is different,
	// we'll fall through to the next pass, which allocates but can
	// handle full set updates.
	for _, n := range nm.Peers {
		if ep, ok := c.peerMap.endpointForNodeKey(n.Key); ok {
			if n.DiscoKey.IsZero() && !n.IsWireGuardOnly {
				// Discokey transitioned from non-zero to zero? This should not
				// happen in the wild, however it could mean:
				// 1. A node was downgraded from post 0.100 to pre 0.100.
				// 2. A Tailscale node key was extracted and used on a
				//    non-Tailscale node (should not enter here due to the
				//    IsWireGuardOnly check)
				// 3. The server is misbehaving.
				c.peerMap.deleteEndpoint(ep)
				continue
			}
			var oldDiscoKey key.DiscoPublic
			if epDisco := ep.disco.Load(); epDisco != nil {
				oldDiscoKey = epDisco.key
			}
			ep.updateFromNode(n, heartbeatDisabled)
			c.peerMap.upsertEndpoint(ep, oldDiscoKey) // maybe update discokey mappings in peerMap
			continue
		}
		if n.DiscoKey.IsZero() && !n.IsWireGuardOnly {
			// Ancient pre-0.100 node, which does not have a disco key, and will only be reachable via DERP.
			continue
		}

		ep := &endpoint{
			c:                 c,
			debugUpdates:      ringbuffer.New[EndpointChange](entriesPerBuffer),
			publicKey:         n.Key,
			publicKeyHex:      n.Key.UntypedHexString(),
			blockEndpoints:    c.blockEndpoints,
			sentPing:          map[stun.TxID]sentPing{},
			endpointState:     map[netip.AddrPort]*endpointState{},
			heartbeatDisabled: heartbeatDisabled,
			isWireguardOnly:   n.IsWireGuardOnly,
		}
		for _, addr := range n.Addresses {
			// Only set nodeAddr if it's a DERP address while endpoints are
			// blocked.
			if !c.blockEndpoints || addr.Addr() == tailcfg.DerpMagicIPAddr {
				ep.nodeAddr = addr.Addr()
				break
			}
		}
		ep.initFakeUDPAddr()
		if n.DiscoKey.IsZero() {
			ep.disco.Store(nil)
		} else {
			ep.disco.Store(&endpointDisco{
				key:   n.DiscoKey,
				short: n.DiscoKey.ShortString(),
			})

			if debugDisco() { // rather than making a new knob
				c.logf("magicsock: created endpoint key=%s: disco=%s; %v", n.Key.ShortString(), n.DiscoKey.ShortString(), logger.ArgWriter(func(w *bufio.Writer) {
					const derpPrefix = "127.3.3.40:"
					if strings.HasPrefix(n.DERP, derpPrefix) {
						ipp, _ := netip.ParseAddrPort(n.DERP)
						regionID := int(ipp.Port())
						code := c.derpRegionCodeLocked(regionID)
						if code != "" {
							code = "(" + code + ")"
						}
						fmt.Fprintf(w, "derp=%v%s ", regionID, code)
					}

					for _, a := range n.AllowedIPs {
						if a.IsSingleIP() {
							fmt.Fprintf(w, "aip=%v ", a.Addr())
						} else {
							fmt.Fprintf(w, "aip=%v ", a)
						}
					}
					for _, ep := range n.Endpoints {
						fmt.Fprintf(w, "ep=%v ", ep)
					}
				}))
			}
		}
		ep.updateFromNode(n, heartbeatDisabled)
		c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
	}

	// If the set of nodes changed since the last SetNetworkMap, the
	// upsert loop just above made c.peerMap contain the union of the
	// old and new peers - which will be larger than the set from the
	// current netmap. If that happens, go through the allocful
	// deletion path to clean up moribund nodes.
	if c.peerMap.nodeCount() != len(nm.Peers) {
		keep := make(map[key.NodePublic]bool, len(nm.Peers))
		for _, n := range nm.Peers {
			keep[n.Key] = true
		}
		c.peerMap.forEachEndpoint(func(ep *endpoint) {
			if !keep[ep.publicKey] {
				c.peerMap.deleteEndpoint(ep)
			}
		})
	}

	// discokeys might have changed in the above. Discard unused info.
	for dk := range c.discoInfo {
		if !c.peerMap.anyEndpointForDiscoKey(dk) {
			delete(c.discoInfo, dk)
		}
	}
}

func (c *Conn) logEndpointChange(endpoints []tailcfg.Endpoint) {
	c.logf("magicsock: endpoints changed: %s", logger.ArgWriter(func(buf *bufio.Writer) {
		for i, ep := range endpoints {
			if i > 0 {
				buf.WriteString(", ")
			}
			fmt.Fprintf(buf, "%s (%s)", ep.Addr, ep.Type)
		}
	}))
}

// Bind returns the wireguard-go conn.Bind for c.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind
func (c *Conn) Bind() conn.Bind {
	return c.bind
}

// connBind is a wireguard-go conn.Bind for a Conn.
// It bridges the behavior of wireguard-go and a Conn.
// wireguard-go calls Close then Open on device.Up.
// That won't work well for a Conn, which is only closed on shutdown.
// The subsequent Close is a real close.
type connBind struct {
	*Conn
	mu     sync.Mutex
	closed bool
}

// This is a compile-time assertion that connBind implements the wireguard-go
// conn.Bind interface.
var _ conn.Bind = (*connBind)(nil)

// BatchSize returns the number of buffers expected to be passed to
// the ReceiveFuncs, and the maximum expected to be passed to SendBatch.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.BatchSize
func (c *connBind) BatchSize() int {
	// TODO(raggi): determine by properties rather than hardcoding platform behavior
	switch runtime.GOOS {
	case "linux":
		return conn.IdealBatchSize
	default:
		return 1
	}
}

// Open is called by WireGuard to create a UDP binding.
// The ignoredPort comes from wireguard-go, via the wgcfg config.
// We ignore that port value here, since we have the local port available easily.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.Open
func (c *connBind) Open(ignoredPort uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return nil, 0, errors.New("magicsock: connBind already open")
	}
	c.closed = false
	fns := []conn.ReceiveFunc{c.receiveIPv4(), c.receiveIPv6(), c.receiveDERP}
	if runtime.GOOS == "js" {
		fns = []conn.ReceiveFunc{c.receiveDERP}
	}
	// TODO: Combine receiveIPv4 and receiveIPv6 and receiveIP into a single
	// closure that closes over a *RebindingUDPConn?
	return fns, c.LocalPort(), nil
}

// SetMark is used by wireguard-go to set a mark bit for packets to avoid routing loops.
// We handle that ourselves elsewhere.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.SetMark
func (c *connBind) SetMark(value uint32) error {
	return nil
}

// Close closes the connBind, unless it is already closed.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.Close
func (c *connBind) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// Unblock all outstanding receives.
	c.pconn4.Close()
	c.pconn6.Close()
	if c.closeDisco4 != nil {
		c.closeDisco4.Close()
	}
	if c.closeDisco6 != nil {
		c.closeDisco6.Close()
	}
	// Send an empty read result to unblock receiveDERP,
	// which will then check connBind.Closed.
	// connBind.Closed takes c.mu, but c.derpRecvCh is buffered.
	c.derpRecvCh <- derpReadResult{}
	return nil
}

// isClosed reports whether c is closed.
func (c *connBind) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Close closes the connection.
//
// Only the first close does anything. Any later closes return nil.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closing.Store(true)
	if c.derpCleanupTimerArmed {
		c.derpCleanupTimer.Stop()
	}
	c.stopPeriodicReSTUNTimerLocked()
	c.portMapper.Close()

	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.stopAndReset()
	})

	c.closed = true
	c.connCtxCancel()
	c.closeAllDerpLocked("conn-close")
	// Ignore errors from c.pconnN.Close.
	// They will frequently have been closed already by a call to connBind.Close.
	c.pconn6.Close()
	c.pconn4.Close()

	// Wait on goroutines updating right at the end, once everything is
	// already closed. We want everything else in the Conn to be
	// consistently in the closed state before we release mu to wait
	// on the endpoint updater & derphttp.Connect.
	for c.goroutinesRunningLocked() {
		c.muCond.Wait()
	}

	if pinger := c.getPinger(); pinger != nil {
		pinger.Close()
	}

	return nil
}

func (c *Conn) goroutinesRunningLocked() bool {
	if c.endpointsUpdateActive {
		return true
	}
	// The goroutine running dc.Connect in derpWriteChanOfAddr may linger
	// and appear to leak, as observed in https://github.com/tailscale/tailscale/issues/554.
	// This is despite the underlying context being cancelled by connCtxCancel above.
	// To avoid this condition, we must wait on derpStarted here
	// to ensure that this goroutine has exited by the time Close returns.
	// We only do this if derpWriteChanOfAddr has executed at least once:
	// on the first run, it sets firstDerp := true and spawns the aforementioned goroutine.
	// To detect this, we check activeDerp, which is initialized to non-nil on the first run.
	if c.activeDerp != nil {
		select {
		case <-c.derpStarted:
		default:
			return true
		}
	}
	return false
}

func (c *Conn) shouldDoPeriodicReSTUNLocked() bool {
	if c.networkDown() {
		return false
	}
	if len(c.peerSet) == 0 || c.privateKey.IsZero() {
		// If no peers, not worth doing.
		// Also don't if there's no key (not running).
		return false
	}
	if f := c.idleFunc; f != nil {
		idleFor := f()
		if debugReSTUNStopOnIdle() {
			c.logf("magicsock: periodicReSTUN: idle for %v", idleFor.Round(time.Second))
		}
		if idleFor > sessionActiveTimeout {
			if c.netMap != nil && c.netMap.Debug != nil && c.netMap.Debug.ForceBackgroundSTUN {
				// Overridden by control.
				return true
			}
			return false
		}
	}
	return true
}

func (c *Conn) onPortMapChanged() { c.ReSTUN("portmap-changed") }

// ReSTUN triggers an address discovery.
// The provided why string is for debug logging only.
func (c *Conn) ReSTUN(why string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		// raced with a shutdown.
		return
	}
	metricReSTUNCalls.Add(1)

	// If the user stopped the app, stop doing work. (When the
	// user stops Tailscale via the GUI apps, ipn/local.go
	// reconfigures the engine with a zero private key.)
	//
	// This used to just check c.privateKey.IsZero, but that broke
	// some end-to-end tests that didn't ever set a private
	// key somehow. So for now, only stop doing work if we ever
	// had a key, which helps real users, but appeases tests for
	// now. TODO: rewrite those tests to be less brittle or more
	// realistic.
	if c.privateKey.IsZero() && c.everHadKey {
		c.logf("magicsock: ReSTUN(%q) ignored; stopped, no private key", why)
		return
	}

	if c.endpointsUpdateActive {
		if c.wantEndpointsUpdate != why {
			c.dlogf("[v1] magicsock: ReSTUN: endpoint update active, need another later (%q)", why)
			c.wantEndpointsUpdate = why
		}
	} else {
		c.endpointsUpdateActive = true
		go c.updateEndpoints(why)
	}
}

// listenPacket opens a packet listener.
// The network must be "udp4" or "udp6".
func (c *Conn) listenPacket(network string, port uint16) (nettype.PacketConn, error) {
	ctx := context.Background() // unused without DNS name to resolve
	if network == "udp4" {
		ctx = sockstats.WithSockStats(ctx, sockstats.LabelMagicsockConnUDP4, c.logf)
	} else {
		ctx = sockstats.WithSockStats(ctx, sockstats.LabelMagicsockConnUDP6, c.logf)
	}
	addr := net.JoinHostPort("", fmt.Sprint(port))
	if c.testOnlyPacketListener != nil {
		return nettype.MakePacketListenerWithNetIP(c.testOnlyPacketListener).ListenPacket(ctx, network, addr)
	}
	return nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf, c.netMon)).ListenPacket(ctx, network, addr)
}

// bindSocket initializes rucPtr if necessary and binds a UDP socket to it.
// Network indicates the UDP socket type; it must be "udp4" or "udp6".
// If rucPtr had an existing UDP socket bound, it closes that socket.
// The caller is responsible for informing the portMapper of any changes.
// If curPortFate is set to dropCurrentPort, no attempt is made to reuse
// the current port.
func (c *Conn) bindSocket(ruc *RebindingUDPConn, network string, curPortFate currentPortFate) error {
	if debugBindSocket() {
		c.logf("magicsock: bindSocket: network=%q curPortFate=%v", network, curPortFate)
	}

	// Hold the ruc lock the entire time, so that the close+bind is atomic
	// from the perspective of ruc receive functions.
	ruc.mu.Lock()
	defer ruc.mu.Unlock()

	if runtime.GOOS == "js" {
		ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize())
		return nil
	}

	if debugAlwaysDERP() {
		c.logf("disabled %v per TS_DEBUG_ALWAYS_USE_DERP", network)
		ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize())
		return nil
	}

	// Build a list of preferred ports.
	// Best is the port that the user requested.
	// Second best is the port that is currently in use.
	// If those fail, fall back to 0.
	var ports []uint16
	if port := uint16(c.port.Load()); port != 0 {
		ports = append(ports, port)
	}
	if ruc.pconn != nil && curPortFate == keepCurrentPort {
		curPort := uint16(ruc.localAddrLocked().Port)
		ports = append(ports, curPort)
	}
	ports = append(ports, 0)
	// Remove duplicates. (All duplicates are consecutive.)
	uniq.ModifySlice(&ports)

	if debugBindSocket() {
		c.logf("magicsock: bindSocket: candidate ports: %+v", ports)
	}

	var pconn nettype.PacketConn
	for _, port := range ports {
		// Close the existing conn, in case it is sitting on the port we want.
		err := ruc.closeLocked()
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errNilPConn) {
			c.logf("magicsock: bindSocket %v close failed: %v", network, err)
		}
		// Open a new one with the desired port.
		pconn, err = c.listenPacket(network, port)
		if err != nil {
			c.logf("magicsock: unable to bind %v port %d: %v", network, port, err)
			continue
		}
		trySetSocketBuffer(pconn, c.logf)
		// CODER: https://github.com/coder/coder/issues/15523
		// Attempt to tell the OS not to fragment packets over this interface. We pad disco Ping and Pong packets to the
		// size of the direct UDP packets that get sent for direct connections. Thus, any interfaces or paths that
		// cannot fully support direct connections due to MTU limitations will not be selected. If no direct paths meet
		// the MTU requirements for a peer, we will fall back to DERP for that peer.
		tryPreventFragmentation(pconn, c.logf, network)
		// Success.
		if debugBindSocket() {
			c.logf("magicsock: bindSocket: successfully listened %v port %d", network, port)
		}
		ruc.setConnLocked(pconn, network, c.bind.BatchSize())
		if network == "udp4" {
			health.SetUDP4Unbound(false)
		}
		return nil
	}

	// Failed to bind, including on port 0 (!).
	// Set pconn to a dummy conn whose reads block until closed.
	// This keeps the receive funcs alive for a future in which
	// we get a link change and we can try binding again.
	ruc.setConnLocked(newBlockForeverConn(), "", c.bind.BatchSize())
	if network == "udp4" {
		health.SetUDP4Unbound(true)
	}
	return fmt.Errorf("failed to bind any ports (tried %v)", ports)
}

type currentPortFate uint8

const (
	keepCurrentPort = currentPortFate(0)
	dropCurrentPort = currentPortFate(1)
)

// rebind closes and re-binds the UDP sockets.
// We consider it successful if we manage to bind the IPv4 socket.
func (c *Conn) rebind(curPortFate currentPortFate) error {
	if err := c.bindSocket(&c.pconn6, "udp6", curPortFate); err != nil {
		c.logf("magicsock: Rebind ignoring IPv6 bind failure: %v", err)
	}
	if err := c.bindSocket(&c.pconn4, "udp4", curPortFate); err != nil {
		return fmt.Errorf("magicsock: Rebind IPv4 failed: %w", err)
	}
	c.portMapper.SetLocalPort(c.LocalPort())
	return nil
}

// Rebind closes and re-binds the UDP sockets and resets the DERP connection.
// It should be followed by a call to ReSTUN.
func (c *Conn) Rebind() {
	metricRebindCalls.Add(1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	err := c.rebind(keepCurrentPort)
	c.mu.Unlock()
	if err != nil {
		c.logf("%w", err)
		return
	}

	var ifIPs []netip.Prefix
	if c.netMon != nil {
		st := c.netMon.InterfaceState()
		defIf := st.DefaultRouteInterface
		ifIPs = st.InterfaceIPs[defIf]
		c.logf("Rebind; defIf=%q, ips=%v", defIf, ifIPs)
	}

	c.maybeCloseDERPsOnRebind(ifIPs)
	c.resetEndpointStates()
}

// resetEndpointStates resets the preferred address for all peers.
// This is called when connectivity changes enough that we no longer
// trust the old routes.
func (c *Conn) resetEndpointStates() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(ep *endpoint) {
		ep.noteConnectivityChange()
	})
}

// packIPPort packs an IPPort into the form wanted by WireGuard.
func packIPPort(ua netip.AddrPort) []byte {
	ip := ua.Addr().Unmap()
	a := ip.As16()
	ipb := a[:]
	if ip.Is4() {
		ipb = ipb[12:]
	}
	b := make([]byte, 0, len(ipb)+2)
	b = append(b, ipb...)
	b = append(b, byte(ua.Port()))
	b = append(b, byte(ua.Port()>>8))
	return b
}

// ParseEndpoint implements conn.Bind; it's called by WireGuard to connect to an endpoint.
//
// See https://pkg.go.dev/golang.zx2c4.com/wireguard/conn#Bind.ParseEndpoint
func (c *Conn) ParseEndpoint(nodeKeyStr string) (conn.Endpoint, error) {
	k, err := key.ParseNodePublicUntyped(mem.S(nodeKeyStr))
	if err != nil {
		return nil, fmt.Errorf("magicsock: ParseEndpoint: parse failed on %q: %w", nodeKeyStr, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errConnClosed
	}
	ep, ok := c.peerMap.endpointForNodeKey(k)
	if !ok {
		// We should never be telling WireGuard about a new peer
		// before magicsock knows about it.
		c.logf("[unexpected] magicsock: ParseEndpoint: unknown node key=%s", k.ShortString())
		return nil, fmt.Errorf("magicsock: ParseEndpoint: unknown peer %q", k.ShortString())
	}

	return ep, nil
}

func (c *batchingUDPConn) writeBatch(msgs []ipv6.Message) error {
	var head int
	for {
		n, err := c.xpc.WriteBatch(msgs[head:], 0)
		if err != nil || n == len(msgs[head:]) {
			// Returning the number of packets written would require
			// unraveling individual msg len and gso size during a coalesced
			// write. The top of the call stack disregards partial success,
			// so keep this simple for now.
			return err
		}
		head += n
	}
}

// splitCoalescedMessages splits coalesced messages from the tail of dst
// beginning at index 'firstMsgAt' into the head of the same slice. It reports
// the number of elements to evaluate in msgs for nonzero len (msgs[i].N). An
// error is returned if a socket control message cannot be parsed or a split
// operation would overflow msgs.
func (c *batchingUDPConn) splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int) (n int, err error) {
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, err
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		gsoSize, err = c.getGSOSizeFromControl(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			// It is legal for bytes to move within msg.Buffers[0] as a result
			// of splitting, so we only zero the source msg len when it is not
			// the destination of the last split operation above.
			msg.N = 0
		}
	}
	return n, nil
}

func (c *batchingUDPConn) ReadBatch(msgs []ipv6.Message, flags int) (n int, err error) {
	if !c.rxOffload || len(msgs) < 2 {
		return c.xpc.ReadBatch(msgs, flags)
	}
	// Read into the tail of msgs, split into the head.
	readAt := len(msgs) - 2
	numRead, err := c.xpc.ReadBatch(msgs[readAt:], 0)
	if err != nil || numRead == 0 {
		return 0, err
	}
	return c.splitCoalescedMessages(msgs, readAt)
}

func (c *batchingUDPConn) LocalAddr() net.Addr {
	return c.pc.LocalAddr().(*net.UDPAddr)
}

func (c *batchingUDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.pc.WriteToUDPAddrPort(b, addr)
}

func (c *batchingUDPConn) Close() error {
	return c.pc.Close()
}

// tryUpgradeToBatchingUDPConn probes the capabilities of the OS and pconn, and
// upgrades pconn to a *batchingUDPConn if appropriate.
func tryUpgradeToBatchingUDPConn(pconn nettype.PacketConn, network string, batchSize int) nettype.PacketConn {
	if network != "udp4" && network != "udp6" {
		return pconn
	}
	if runtime.GOOS != "linux" {
		return pconn
	}
	if strings.HasPrefix(hostinfo.GetOSVersion(), "2.") {
		// recvmmsg/sendmmsg were added in 2.6.33, but we support down to
		// 2.6.32 for old NAS devices. See https://github.com/tailscale/tailscale/issues/6807.
		// As a cheap heuristic: if the Linux kernel starts with "2", just
		// consider it too old for mmsg. Nobody who cares about performance runs
		// such ancient kernels. UDP offload was added much later, so no
		// upgrades are available.
		return pconn
	}
	uc, ok := pconn.(*net.UDPConn)
	if !ok {
		return pconn
	}
	b := &batchingUDPConn{
		pc:                    pconn,
		getGSOSizeFromControl: getGSOSizeFromControl,
		setGSOSizeInControl:   setGSOSizeInControl,
		sendBatchPool: sync.Pool{
			New: func() any {
				ua := &net.UDPAddr{
					IP: make([]byte, 16),
				}
				msgs := make([]ipv6.Message, batchSize)
				for i := range msgs {
					msgs[i].Buffers = make([][]byte, 1)
					msgs[i].Addr = ua
					msgs[i].OOB = make([]byte, controlMessageSize)
				}
				return &sendBatch{
					ua:   ua,
					msgs: msgs,
				}
			},
		},
	}
	switch network {
	case "udp4":
		b.xpc = ipv4.NewPacketConn(uc)
	case "udp6":
		b.xpc = ipv6.NewPacketConn(uc)
	default:
		panic("bogus network")
	}
	var txOffload bool
	txOffload, b.rxOffload = tryEnableUDPOffload(uc)
	b.txOffload.Store(txOffload)
	return b
}

func newBlockForeverConn() *blockForeverConn {
	c := new(blockForeverConn)
	c.cond = sync.NewCond(&c.mu)
	return c
}

// simpleDur rounds d such that it stringifies to something short.
func simpleDur(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(time.Millisecond)
	}
	if d < time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(time.Minute)
}

func (c *Conn) UpdateStatus(sb *ipnstate.StatusBuilder) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var tailscaleIPs []netip.Addr
	if c.netMap != nil {
		tailscaleIPs = make([]netip.Addr, 0, len(c.netMap.Addresses))
		for _, addr := range c.netMap.Addresses {
			if !addr.IsSingleIP() {
				continue
			}
			sb.AddTailscaleIP(addr.Addr())
			tailscaleIPs = append(tailscaleIPs, addr.Addr())
		}
	}

	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		if !c.privateKey.IsZero() {
			ss.PublicKey = c.privateKey.Public()
		} else {
			ss.PublicKey = key.NodePublic{}
		}
		ss.Addrs = make([]string, 0, len(c.lastEndpoints))
		for _, ep := range c.lastEndpoints {
			ss.Addrs = append(ss.Addrs, ep.Addr.String())
		}
		ss.OS = version.OS()
		if c.derpMap != nil {
			derpRegion, ok := c.derpMap.Regions[c.myDerp]
			if ok {
				ss.Relay = derpRegion.RegionCode
			}
		}
		ss.TailscaleIPs = tailscaleIPs
	})

	if sb.WantPeers {
		c.peerMap.forEachEndpoint(func(ep *endpoint) {
			ps := &ipnstate.PeerStatus{InMagicSock: true}
			//ps.Addrs = append(ps.Addrs, n.Endpoints...)
			ep.populatePeerStatus(ps)
			sb.AddPeer(ep.publicKey, ps)
		})
	}

	c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
		// TODO(bradfitz): add to ipnstate.StatusBuilder
		//f("<li><b>derp-%v</b>: cr%v,wr%v</li>", node, simpleDur(now.Sub(ad.createTime)), simpleDur(now.Sub(*ad.lastWrite)))
	})
}

// SetStatistics specifies a per-connection statistics aggregator.
// Nil may be specified to disable statistics gathering.
func (c *Conn) SetStatistics(stats *connstats.Statistics) {
	c.stats.Store(stats)
}

const (
	// sessionActiveTimeout is how long since the last activity we
	// try to keep an established endpoint peering alive.
	// It's also the idle time at which we stop doing STUN queries to
	// keep NAT mappings alive.
	sessionActiveTimeout = 45 * time.Second

	// upgradeInterval is how often we try to upgrade to a better path
	// even if we have some non-DERP route that works.
	upgradeInterval = 1 * time.Minute

	// heartbeatInterval is how often pings to the best UDP address
	// are sent.
	heartbeatInterval = 3 * time.Second

	// trustUDPAddrDuration is how long we trust a UDP address as the exclusive
	// path (without using DERP) without having heard a Pong reply.
	trustUDPAddrDuration = 6500 * time.Millisecond

	// goodEnoughLatency is the latency at or under which we don't
	// try to upgrade to a better path.
	goodEnoughLatency = 5 * time.Millisecond

	// endpointsFreshEnoughDuration is how long we consider a
	// STUN-derived endpoint valid for. UDP NAT mappings typically
	// expire at 30 seconds, so this is a few seconds shy of that.
	endpointsFreshEnoughDuration = 27 * time.Second

	// endpointTrackerLifetime is how long we continue advertising an
	// endpoint after we last see it. This is intentionally chosen to be
	// slightly longer than a full netcheck period.
	endpointTrackerLifetime = 5*time.Minute + 10*time.Second
)

// Constants that are variable for testing.
var (
	// pingTimeoutDuration is how long we wait for a pong reply before
	// assuming it's never coming.
	pingTimeoutDuration = 5 * time.Second

	// discoPingInterval is the minimum time between pings
	// to an endpoint. (Except in the case of CallMeMaybe frames
	// resetting the counter, as the first pings likely didn't through
	// the firewall)
	discoPingInterval = 5 * time.Second
)

// indexSentinelDeleted is the temporary value that endpointState.index takes while
// a endpoint's endpoints are being updated from a new network map.
const indexSentinelDeleted = -1

// getPinger lazily instantiates a pinger and returns it, if it was
// already instantiated it returns the existing one.
func (c *Conn) getPinger() *ping.Pinger {
	return c.wgPinger.Get(func() *ping.Pinger {
		return ping.New(c.connCtx, c.dlogf, netns.Listener(c.logf, c.netMon))
	})
}

// portableTrySetSocketBuffer sets SO_SNDBUF and SO_RECVBUF on pconn to socketBufferSize,
// logging an error if it occurs.
func portableTrySetSocketBuffer(pconn nettype.PacketConn, logf logger.Logf) {
	if c, ok := pconn.(*net.UDPConn); ok {
		// Attempt to increase the buffer size, and allow failures.
		if err := c.SetReadBuffer(socketBufferSize); err != nil {
			logf("magicsock: failed to set UDP read buffer size to %d: %v", socketBufferSize, err)
		}
		if err := c.SetWriteBuffer(socketBufferSize); err != nil {
			logf("magicsock: failed to set UDP write buffer size to %d: %v", socketBufferSize, err)
		}
	}
}

// derpStr replaces DERP IPs in s with "derp-".
func derpStr(s string) string { return strings.ReplaceAll(s, "127.3.3.40:", "derp-") }

// ippEndpointCache is a mutex-free single-element cache, mapping from
// a single netip.AddrPort to a single endpoint.
type ippEndpointCache struct {
	ipp netip.AddrPort
	gen int64
	de  *endpoint
}

// discoInfo is the info and state for the DiscoKey
// in the Conn.discoInfo map key.
//
// Note that a DiscoKey does not necessarily map to exactly one
// node. In the case of shared nodes and users switching accounts, two
// nodes in the NetMap may legitimately have the same DiscoKey.  As
// such, no fields in here should be considered node-specific.
type discoInfo struct {
	// discoKey is the same as the Conn.discoInfo map key,
	// just so you can pass around a *discoInfo alone.
	// Not modified once initialized.
	discoKey key.DiscoPublic

	// discoShort is discoKey.ShortString().
	// Not modified once initialized;
	discoShort string

	// sharedKey is the precomputed key for communication with the
	// peer that has the DiscoKey used to look up this *discoInfo in
	// Conn.discoInfo.
	// Not modified once initialized.
	sharedKey key.DiscoShared

	// Mutable fields follow, owned by Conn.mu:

	// lastPingFrom is the src of a ping for discoKey.
	lastPingFrom netip.AddrPort

	// lastPingTime is the last time of a ping for discoKey.
	lastPingTime time.Time
}

type endpointTrackerEntry struct {
	endpoint tailcfg.Endpoint
	until    time.Time
}

type endpointTracker struct {
	mu    sync.Mutex
	cache map[netip.AddrPort]endpointTrackerEntry
}

func (et *endpointTracker) update(now time.Time, eps []tailcfg.Endpoint) (epsPlusCached []tailcfg.Endpoint) {
	epsPlusCached = eps

	var inputEps set.Slice[netip.AddrPort]
	for _, ep := range eps {
		inputEps.Add(ep.Addr)
	}

	et.mu.Lock()
	defer et.mu.Unlock()

	// Add entries to the return array that aren't already there.
	for k, ep := range et.cache {
		// If the endpoint was in the input list, or has expired, skip it.
		if inputEps.Contains(k) {
			continue
		} else if now.After(ep.until) {
			continue
		}

		// We haven't seen this endpoint; add to the return array
		epsPlusCached = append(epsPlusCached, ep.endpoint)
	}

	// Add entries from the original input array into the cache, and/or
	// extend the lifetime of entries that are already in the cache.
	until := now.Add(endpointTrackerLifetime)
	for _, ep := range eps {
		et.addLocked(now, ep, until)
	}

	// Remove everything that has now expired.
	et.removeExpiredLocked(now)
	return epsPlusCached
}

// add will store the provided endpoint(s) in the cache for a fixed period of
// time, and remove any entries in the cache that have expired.
//
// et.mu must be held.
func (et *endpointTracker) addLocked(now time.Time, ep tailcfg.Endpoint, until time.Time) {
	// If we already have an entry for this endpoint, update the timeout on
	// it; otherwise, add it.
	entry, found := et.cache[ep.Addr]
	if found {
		entry.until = until
	} else {
		entry = endpointTrackerEntry{ep, until}
	}
	mak.Set(&et.cache, ep.Addr, entry)
}

// removeExpired will remove all expired entries from the cache
//
// et.mu must be held
func (et *endpointTracker) removeExpiredLocked(now time.Time) {
	for k, ep := range et.cache {
		if now.After(ep.until) {
			delete(et.cache, k)
		}
	}
}

var (
	metricNumPeers     = clientmetric.NewGauge("magicsock_netmap_num_peers")
	metricNumDERPConns = clientmetric.NewGauge("magicsock_num_derp_conns")

	metricRebindCalls     = clientmetric.NewCounter("magicsock_rebind_calls")
	metricReSTUNCalls     = clientmetric.NewCounter("magicsock_restun_calls")
	metricUpdateEndpoints = clientmetric.NewCounter("magicsock_update_endpoints")

	// Sends (data or disco)
	metricSendDERPQueued      = clientmetric.NewCounter("magicsock_send_derp_queued")
	metricSendDERPErrorChan   = clientmetric.NewCounter("magicsock_send_derp_error_chan")
	metricSendDERPErrorClosed = clientmetric.NewCounter("magicsock_send_derp_error_closed")
	metricSendDERPErrorQueue  = clientmetric.NewCounter("magicsock_send_derp_error_queue")
	metricSendUDP             = clientmetric.NewCounter("magicsock_send_udp")
	metricSendUDPError        = clientmetric.NewCounter("magicsock_send_udp_error")
	metricSendDERP            = clientmetric.NewCounter("magicsock_send_derp")
	metricSendDERPError       = clientmetric.NewCounter("magicsock_send_derp_error")

	// Data packets (non-disco)
	metricSendData            = clientmetric.NewCounter("magicsock_send_data")
	metricSendDataNetworkDown = clientmetric.NewCounter("magicsock_send_data_network_down")
	metricRecvDataDERP        = clientmetric.NewCounter("magicsock_recv_data_derp")
	metricRecvDataIPv4        = clientmetric.NewCounter("magicsock_recv_data_ipv4")
	metricRecvDataIPv6        = clientmetric.NewCounter("magicsock_recv_data_ipv6")

	// Disco packets
	metricSendDiscoUDP         = clientmetric.NewCounter("magicsock_disco_send_udp")
	metricSendDiscoDERP        = clientmetric.NewCounter("magicsock_disco_send_derp")
	metricSentDiscoUDP         = clientmetric.NewCounter("magicsock_disco_sent_udp")
	metricSentDiscoDERP        = clientmetric.NewCounter("magicsock_disco_sent_derp")
	metricSentDiscoPing        = clientmetric.NewCounter("magicsock_disco_sent_ping")
	metricSentDiscoPong        = clientmetric.NewCounter("magicsock_disco_sent_pong")
	metricSentDiscoCallMeMaybe = clientmetric.NewCounter("magicsock_disco_sent_callmemaybe")
	metricRecvDiscoBadPeer     = clientmetric.NewCounter("magicsock_disco_recv_bad_peer")
	metricRecvDiscoBadKey      = clientmetric.NewCounter("magicsock_disco_recv_bad_key")
	metricRecvDiscoBadParse    = clientmetric.NewCounter("magicsock_disco_recv_bad_parse")

	metricRecvDiscoUDP                 = clientmetric.NewCounter("magicsock_disco_recv_udp")
	metricRecvDiscoDERP                = clientmetric.NewCounter("magicsock_disco_recv_derp")
	metricRecvDiscoPing                = clientmetric.NewCounter("magicsock_disco_recv_ping")
	metricRecvDiscoPong                = clientmetric.NewCounter("magicsock_disco_recv_pong")
	metricRecvDiscoCallMeMaybe         = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe")
	metricRecvDiscoCallMeMaybeBadNode  = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe_bad_node")
	metricRecvDiscoCallMeMaybeBadDisco = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe_bad_disco")
	metricRecvDiscoDERPPeerNotHere     = clientmetric.NewCounter("magicsock_disco_recv_derp_peer_not_here")
	metricRecvDiscoDERPPeerGoneUnknown = clientmetric.NewCounter("magicsock_disco_recv_derp_peer_gone_unknown")
	// metricDERPHomeChange is how many times our DERP home region DI has
	// changed from non-zero to a different non-zero.
	metricDERPHomeChange = clientmetric.NewCounter("derp_home_change")

	// Disco packets received bpf read path
	metricRecvDiscoPacketIPv4 = clientmetric.NewCounter("magicsock_disco_recv_bpf_ipv4")
	metricRecvDiscoPacketIPv6 = clientmetric.NewCounter("magicsock_disco_recv_bpf_ipv6")
)
