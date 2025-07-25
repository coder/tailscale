// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netstack wires up gVisor's netstack into Tailscale.
package netstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
)

const debugPackets = false

var debugNetstack = envknob.RegisterBool("TS_DEBUG_NETSTACK")

var coderDNSIPv6 = tsaddr.CoderServiceIPv6()

func init() {
	mode := envknob.String("TS_DEBUG_NETSTACK_LEAK_MODE")
	if mode == "" {
		return
	}
	var lm refs.LeakMode
	if err := lm.Set(mode); err != nil {
		panic(err)
	}
	refs.SetLeakMode(lm)
}

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	// GetTCPHandlerForFlow conditionally handles an incoming TCP flow for the
	// provided (src/port, dst/port) 4-tuple.
	//
	// A nil value is equivalent to a func returning (nil, false).
	//
	// If func returns intercept=false, the default forwarding behavior (if
	// ProcessLocalIPs and/or ProcesssSubnetIPs) takes place.
	//
	// When intercept=true, the behavior depends on whether the returned handler
	// is non-nil: if nil, the connection is rejected. If non-nil, handler takes
	// over the TCP conn.
	GetTCPHandlerForFlow func(src, dst netip.AddrPort) (handler func(net.Conn), opts []tcpip.SettableSocketOption, intercept bool)

	// GetUDPHandlerForFlow conditionally handles an incoming UDP flow for the
	// provided (src/port, dst/port) 4-tuple.
	//
	// A nil value is equivalent to a func returning (nil, false).
	//
	// If func returns intercept=false, the default forwarding behavior (if
	// ProcessLocalIPs and/or ProcesssSubnetIPs) takes place.
	//
	// When intercept=true, the behavior depends on whether the returned handler
	// is non-nil: if nil, the connection is rejected. If non-nil, handler takes
	// over the UDP flow.
	GetUDPHandlerForFlow func(src, dst netip.AddrPort) (handler func(nettype.ConnPacketConn), intercept bool)

	// ProcessLocalIPs is whether netstack should handle incoming
	// traffic directed at the Node.Addresses (local IPs).
	// It can only be set before calling Start.
	ProcessLocalIPs bool

	// ProcessSubnets is whether netstack should handle incoming
	// traffic destined to non-local IPs (i.e. whether it should
	// be a subnet router).
	// It can only be set before calling Start.
	ProcessSubnets bool

	ipstack   *stack.Stack
	epMu      sync.RWMutex
	linkEP    *Endpoint
	tundev    *tstun.Wrapper
	e         wgengine.Engine
	mc        *magicsock.Conn
	logf      logger.Logf
	dialer    *tsdial.Dialer
	ctx       context.Context        // alive until Close
	ctxCancel context.CancelFunc     // called on Close
	lb        *ipnlocal.LocalBackend // or nil
	dns       *dns.Manager

	peerapiPort4Atomic atomic.Uint32 // uint16 port number for IPv4 peerapi
	peerapiPort6Atomic atomic.Uint32 // uint16 port number for IPv6 peerapi

	// atomicIsLocalIPFunc holds a func that reports whether an IP
	// is a local (non-subnet) Tailscale IP address of this
	// machine. It's always a non-nil func. It's changed on netmap
	// updates.
	atomicIsLocalIPFunc syncs.AtomicValue[func(netip.Addr) bool]

	mu sync.Mutex
	// connsOpenBySubnetIP keeps track of number of connections open
	// for each subnet IP temporarily registered on netstack for active
	// TCP connections, so they can be unregistered when connections are
	// closed.
	connsOpenBySubnetIP map[netip.Addr]int
}

const nicID = 1

// maxUDPPacketSize is the maximum size of a UDP packet we copy in startPacketCopy
// when relaying UDP packets. We don't use the 'mtu' const in anticipation of
// one day making the MTU more dynamic.
const maxUDPPacketSize = 1500

const (
	megabytes = 1024 * 1024
	// recvBufSize is the size in bytes for TCP receive buffers.  6MiB is the usual maximum in
	// Linux, but here we set it as the default, because unlike Linux, gVisor does not dynamically
	// resize the buffer based on utilization.  The channel that connects gVisor to Wireguard is 512
	// packets and Wireguard encrypt and decrypt buffers are 1024 packets each, so we could queue
	// 2.5k packets (over 2MiB), even before counting packets in flight on the network.  The TCP
	// window is set to half the recv buffer, or 3 MiB in this case.  Since TCP will only send this
	// much un-ACK'd data, this corresponds to max throughput of 3MiB per RTT (for example, 10 ms
	// RTT is 300 MiB/s or 2.4 Gbit/s).
	recvBufSize = 6 * megabytes
	// sendBufSize is the size in bytes for the TCP send buffers.  4MiB is the usual maximum in
	// Linux.  The send buffer is used for both unsent and un-ACK'd data, so it is important that
	// it is greater than half of the recvBufSize so that there is still room for unsent data from
	// the application.
	sendBufSize = 4 * megabytes
	// CUBIC congestion control is the default in Windows, Linux, and MacOS, and generally achieves
	// better throughput on large, long networks.
	congestionControlCubic = "cubic"
	// maxRetries is the maximum number of retransmissions that the TCP stack should undertake for
	// unacked TCP segments, that is, when we are trying to send TCP data and the other side is
	// unresponsive. It does not affect TCP operation while both sides are idle. The retry timeout
	// has a minimum of 200ms and maximum of 120s, and grows exponentially when the other side is
	// unresponsive. The default maxRetries in gVisor is 15, which means in practice over ten
	// minutes of unresponsiveness before we time out.  Setting to 5 should time out in 15-30s,
	// depending on the latency of the connection.  In Coder's system we depend on Wireguard as the
	// underlay, which retries handshakes on a 5s timer, so we don't want to shorten the timeout
	// less than 15s or so, to give us several chances to re-establish a Wireguard session after
	// idling.
	maxRetries = 5
)

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.Wrapper, e wgengine.Engine, mc *magicsock.Conn, dialer *tsdial.Dialer, dns *dns.Manager) (*Impl, error) {
	if mc == nil {
		return nil, errors.New("nil magicsock.Conn")
	}
	if tundev == nil {
		return nil, errors.New("nil tundev")
	}
	if logf == nil {
		return nil, errors.New("nil logger")
	}
	if e == nil {
		return nil, errors.New("nil Engine")
	}
	if dialer == nil {
		return nil, errors.New("nil Dialer")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	soRecv := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     recvBufSize,
		Default: recvBufSize,
		Max:     recvBufSize,
	}
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &soRecv)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set recv buf size: %v", tcpipErr)
	}
	soSend := tcpip.TCPSendBufferSizeRangeOption{
		Min:     sendBufSize,
		Default: sendBufSize,
		Max:     sendBufSize,
	}
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &soSend)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set send buf size: %v", tcpipErr)
	}
	rack := tcpip.TCPRecovery(0) // Disable RACK
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &rack)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not disable RACK: %v", tcpipErr)
	}
	cc := tcpip.CongestionControlOption(congestionControlCubic)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &cc)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set congestion control: %v", tcpipErr)
	}
	retries := tcpip.TCPMaxRetriesOption(maxRetries)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &retries)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set max retries: %v", tcpipErr)
	}

	linkEP := NewEndpoint(512, tstun.DefaultMTU(), "")
	if tcpipProblem := ipstack.CreateNIC(nicID, linkEP); tcpipProblem != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %v", tcpipProblem)
	}
	// By default the netstack NIC will only accept packets for the IPs
	// registered to it. Since in some cases we dynamically register IPs
	// based on the packets that arrive, the NIC needs to accept all
	// incoming packets. The NIC won't receive anything it isn't meant to
	// since WireGuard will only send us packets that are meant for us.
	ipstack.SetPromiscuousMode(nicID, true)
	// Add IPv4 and IPv6 default routes, so all incoming packets from the Tailscale side
	// are handled by the one fake NIC we use.
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	ipv6Subnet, _ := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})
	ns := &Impl{
		logf:                logf,
		ipstack:             ipstack,
		linkEP:              linkEP,
		tundev:              tundev,
		e:                   e,
		mc:                  mc,
		dialer:              dialer,
		connsOpenBySubnetIP: make(map[netip.Addr]int),
		dns:                 dns,
	}
	ns.ctx, ns.ctxCancel = context.WithCancel(context.Background())
	ns.atomicIsLocalIPFunc.Store(tsaddr.NewContainsIPFunc(nil))
	ns.tundev.PostFilterPacketInboundFromWireGaurd = ns.injectInbound
	ns.tundev.PreFilterPacketOutboundToWireGuardNetstackIntercept = ns.handleLocalPackets
	return ns, nil
}

func (ns *Impl) Close() error {
	ns.ctxCancel()
	// close the linkEP before attempting to close the IP stack, to ensure we unblock writes.
	ns.linkEP.Close()
	ns.ipstack.Close()
	ns.ipstack.Wait()
	return nil
}

// wrapProtoHandler returns protocol handler h wrapped in a version
// that dynamically reconfigures ns's subnet addresses as needed for
// outbound traffic.
func (ns *Impl) wrapProtoHandler(h func(stack.TransportEndpointID, *stack.PacketBuffer) bool) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	return func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		addr := tei.LocalAddress
		ip, ok := netip.AddrFromSlice(addr.AsSlice())
		if !ok {
			ns.logf("netstack: could not parse local address for incoming connection")
			return false
		}
		ip = ip.Unmap()
		if !ns.isLocalIP(ip) {
			ns.addSubnetAddress(ip)
		}
		return h(tei, pb)
	}
}

// Start sets up all the handlers so netstack can start working. Implements
// wgengine.FakeImpl.
func (ns *Impl) Start(lb *ipnlocal.LocalBackend) error {
	if lb != nil {
		ns.lb = lb
	}
	ns.e.AddNetworkMapCallback(ns.updateIPs)
	const maxInFlightConnectionAttempts = 1024
	tcpFwd := tcp.NewForwarder(ns.ipstack, recvBufSize, maxInFlightConnectionAttempts, ns.acceptTCP)
	udpFwd := udp.NewForwarder(ns.ipstack, ns.acceptUDP)
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, ns.wrapProtoHandler(tcpFwd.HandlePacket))
	ns.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, ns.wrapProtoHandler(udpFwd.HandlePacket))
	go ns.inject()
	return nil
}

func (ns *Impl) addSubnetAddress(ip netip.Addr) {
	ns.mu.Lock()
	ns.connsOpenBySubnetIP[ip]++
	needAdd := ns.connsOpenBySubnetIP[ip] == 1
	ns.mu.Unlock()
	// Only register address into netstack for first concurrent connection.
	if needAdd {
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(ip.AsSlice()),
				PrefixLen: int(ip.BitLen()),
			},
		}
		if ip.Is4() {
			pa.Protocol = ipv4.ProtocolNumber
		} else if ip.Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		ns.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
	}
}

func (ns *Impl) removeSubnetAddress(ip netip.Addr) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.connsOpenBySubnetIP[ip]--
	// Only unregister address from netstack after last concurrent connection.
	if ns.connsOpenBySubnetIP[ip] == 0 {
		ns.ipstack.RemoveAddress(nicID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(ns.connsOpenBySubnetIP, ip)
	}
}

func ipPrefixToAddressWithPrefix(ipp netip.Prefix) tcpip.AddressWithPrefix {
	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		PrefixLen: int(ipp.Bits()),
	}
}

var v4broadcast = netaddr.IPv4(255, 255, 255, 255)

func (ns *Impl) updateIPs(nm *netmap.NetworkMap) {
	ns.atomicIsLocalIPFunc.Store(tsaddr.NewContainsIPFunc(nm.Addresses))

	oldIPs := make(map[tcpip.AddressWithPrefix]bool)
	for _, protocolAddr := range ns.ipstack.AllAddresses()[nicID] {
		ap := protocolAddr.AddressWithPrefix
		ip := netaddrIPFromNetstackIP(ap.Address)
		if ip == v4broadcast && ap.PrefixLen == 32 {
			// Don't add 255.255.255.255/32 to oldIPs so we don't
			// delete it later. We didn't install it, so it's not
			// ours to delete.
			continue
		}
		oldIPs[ap] = true
	}
	newIPs := make(map[tcpip.AddressWithPrefix]bool)

	isAddr := map[netip.Prefix]bool{}
	if nm.SelfNode != nil {
		for _, ipp := range nm.SelfNode.Addresses {
			isAddr[ipp] = true
			newIPs[ipPrefixToAddressWithPrefix(ipp)] = true
		}
		for _, ipp := range nm.SelfNode.AllowedIPs {
			if !isAddr[ipp] && ns.ProcessSubnets {
				newIPs[ipPrefixToAddressWithPrefix(ipp)] = true
			}
		}
	}

	ipsToBeAdded := make(map[tcpip.AddressWithPrefix]bool)
	for ipp := range newIPs {
		if !oldIPs[ipp] {
			ipsToBeAdded[ipp] = true
		}
	}
	ipsToBeRemoved := make(map[tcpip.AddressWithPrefix]bool)
	for ip := range oldIPs {
		if !newIPs[ip] {
			ipsToBeRemoved[ip] = true
		}
	}
	ns.mu.Lock()
	for ip := range ns.connsOpenBySubnetIP {
		ipp := tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()
		delete(ipsToBeRemoved, ipp)
	}
	ns.mu.Unlock()

	for ipp := range ipsToBeRemoved {
		err := ns.ipstack.RemoveAddress(nicID, ipp.Address)
		if err != nil {
			ns.logf("netstack: could not deregister IP %s: %v", ipp, err)
		} else {
			ns.logf("[v2] netstack: deregistered IP %s", ipp)
		}
	}
	for ipp := range ipsToBeAdded {
		pa := tcpip.ProtocolAddress{
			AddressWithPrefix: ipp,
		}
		if ipp.Address.Len() == 16 {
			pa.Protocol = ipv6.ProtocolNumber
		} else {
			pa.Protocol = ipv4.ProtocolNumber
		}
		var err tcpip.Error
		err = ns.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
		if err != nil {
			ns.logf("netstack: could not register IP %s: %v", ipp, err)
		} else {
			ns.logf("[v2] netstack: registered IP %s", ipp)
		}
	}
}

// handleLocalPackets is hooked into the tun datapath for packets leaving
// the host and arriving at tailscaled. This method returns filter.DropSilently
// to intercept a packet for handling, for instance traffic to quad-100.
func (ns *Impl) handleLocalPackets(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if ns.ctx.Err() != nil {
		return filter.DropSilently
	}

	// If it's not traffic to the service IP (i.e. magicDNS) we don't
	// care; resume processing.
	if dst := p.Dst.Addr(); dst != coderDNSIPv6 {
		return filter.Accept
	}
	// Of traffic to the service IP, we only care about UDP 53, and TCP
	// on port 80 & 53.
	switch p.IPProto {
	case ipproto.TCP:
		if port := p.Dst.Port(); port != 53 && port != 80 {
			return filter.Accept
		}
	case ipproto.UDP:
		if port := p.Dst.Port(); port != 53 {
			return filter.Accept
		}
	}

	var pn tcpip.NetworkProtocolNumber
	switch p.IPVersion {
	case 4:
		pn = header.IPv4ProtocolNumber
	case 6:
		pn = header.IPv6ProtocolNumber
	}
	if debugPackets {
		ns.logf("[v2] service packet in (from %v): % x", p.Src, p.Buffer())
	}

	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(bytes.Clone(p.Buffer())),
	})
	ns.linkEP.InjectInbound(pn, packetBuf)
	packetBuf.DecRef()
	return filter.DropSilently
}

func (ns *Impl) DialContextTCP(ctx context.Context, ipp netip.AddrPort) (*gonet.TCPConn, error) {
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialContextTCP(ctx, ns.ipstack, remoteAddress, ipType)
}

func (ns *Impl) DialContextUDP(ctx context.Context, ipp netip.AddrPort) (*gonet.UDPConn, error) {
	remoteAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialUDP(ns.ipstack, nil, remoteAddress, ipType)
}

// The inject goroutine reads in packets that netstack generated, and delivers
// them to the correct path.
func (ns *Impl) inject() {
	for {
		pkt := ns.linkEP.ReadContext(ns.ctx)
		if pkt == nil {
			if ns.ctx.Err() != nil {
				// Return without logging.
				return
			}
			ns.logf("[v2] ReadContext-for-write = ok=false")
			continue
		}

		if debugPackets {
			ns.logf("[v2] packet Write out: % x", stack.PayloadSince(pkt.NetworkHeader()))
		}

		// In the normal case, netstack synthesizes the bytes for
		// traffic which should transit back into WG and go to peers.
		// However, some uses of netstack (presently, magic DNS)
		// send traffic destined for the local device, hence must
		// be injected 'inbound'.
		sendToHost := false

		// Determine if the packet is from a service IP, in which case it
		// needs to go back into the machines network (inbound) instead of
		// out.
		// TODO(tom): Work out a way to avoid parsing packets to determine if
		//            its from the service IP. Maybe gvisor netstack magic. I
		//            went through the fields of PacketBuffer, and nop :/
		// TODO(tom): Figure out if its safe to modify packet.Parsed to fill in
		//            the IP src/dest even if its missing the rest of the pkt.
		//            That way we dont have to do this twitchy-af byte-yeeting.
		if b := pkt.NetworkHeader().Slice(); len(b) >= 40 && (b[0]>>4) == 6 { // min ipv6 header && ip proto field
			if srcIP, ok := netip.AddrFromSlice(net.IP(b[8:24])); ok && coderDNSIPv6 == srcIP {
				sendToHost = true
			}
		}

		// pkt has a non-zero refcount, so injection methods takes
		// ownership of one count and will decrement on completion.
		if sendToHost {
			if err := ns.tundev.InjectInboundPacketBuffer(pkt); err != nil {
				log.Printf("netstack inject inbound: %v", err)
				return
			}
		} else {
			if err := ns.tundev.InjectOutboundPacketBuffer(pkt); err != nil {
				log.Printf("netstack inject outbound: %v", err)
				return
			}
		}
	}
}

// isLocalIP reports whether ip is a Tailscale IP assigned to this
// node directly (but not a subnet-routed IP).
func (ns *Impl) isLocalIP(ip netip.Addr) bool {
	return ns.atomicIsLocalIPFunc.Load()(ip)
}

func (ns *Impl) peerAPIPortAtomic(ip netip.Addr) *atomic.Uint32 {
	if ip.Is4() {
		return &ns.peerapiPort4Atomic
	} else {
		return &ns.peerapiPort6Atomic
	}
}

var viaRange = tsaddr.TailscaleViaRange()

// shouldProcessInbound reports whether an inbound packet (a packet from a
// WireGuard peer) should be handled by netstack.
func (ns *Impl) shouldProcessInbound(p *packet.Parsed, t *tstun.Wrapper) bool {
	// Handle incoming peerapi connections in netstack.
	dstIP := p.Dst.Addr()
	isLocal := ns.isLocalIP(dstIP)

	// Handle TCP connection to the Tailscale IP(s) in some cases:
	if ns.lb != nil && p.IPProto == ipproto.TCP && isLocal {
		var peerAPIPort uint16

		if p.TCPFlags&packet.TCPSynAck == packet.TCPSyn {
			if port, ok := ns.lb.GetPeerAPIPort(dstIP); ok {
				peerAPIPort = port
				ns.peerAPIPortAtomic(dstIP).Store(uint32(port))
			}
		} else {
			peerAPIPort = uint16(ns.peerAPIPortAtomic(dstIP).Load())
		}
		dport := p.Dst.Port()
		if dport == peerAPIPort {
			return true
		}
		// Also handle SSH connections, webserver, etc, if enabled:
		if ns.lb.ShouldInterceptTCPPort(dport) {
			return true
		}
	}
	if p.IPVersion == 6 && !isLocal && viaRange.Contains(dstIP) {
		return ns.lb != nil && ns.lb.ShouldHandleViaIP(dstIP)
	}
	if ns.ProcessLocalIPs && isLocal {
		return true
	}
	if ns.ProcessSubnets && !isLocal {
		return true
	}
	return false
}

// setAmbientCapsRaw is non-nil on Linux for Synology, to run ping with
// CAP_NET_RAW from tailscaled's binary.
var setAmbientCapsRaw func(*exec.Cmd)

var userPingSem = syncs.NewSemaphore(20) // 20 child ping processes at once

var isSynology = runtime.GOOS == "linux" && distro.Get() == distro.Synology

// userPing tried to ping dstIP and if it succeeds, injects pingResPkt
// into the tundev.
//
// It's used in userspace/netstack mode when we don't have kernel
// support or raw socket access. As such, this does the dumbest thing
// that can work: runs the ping command. It's not super efficient, so
// it bounds the number of pings going on at once. The idea is that
// people only use ping occasionally to see if their internet's working
// so this doesn't need to be great.
//
// TODO(bradfitz): when we're running on Windows as the system user, use
// raw socket APIs instead of ping child processes.
func (ns *Impl) userPing(dstIP netip.Addr, pingResPkt []byte) {
	if !userPingSem.TryAcquire() {
		return
	}
	defer userPingSem.Release()

	t0 := time.Now()
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("ping", "-n", "1", "-w", "3000", dstIP.String()).Run()
	case "darwin", "freebsd":
		// Note: 2000 ms is actually 1 second + 2,000
		// milliseconds extra for 3 seconds total.
		// See https://github.com/tailscale/tailscale/pull/3753 for details.
		ping := "ping"
		if dstIP.Is6() {
			ping = "ping6"
		}
		err = exec.Command(ping, "-c", "1", "-W", "2000", dstIP.String()).Run()
	case "openbsd":
		ping := "ping"
		if dstIP.Is6() {
			ping = "ping6"
		}
		err = exec.Command(ping, "-c", "1", "-w", "3", dstIP.String()).Run()
	case "android":
		ping := "/system/bin/ping"
		if dstIP.Is6() {
			ping = "/system/bin/ping6"
		}
		err = exec.Command(ping, "-c", "1", "-w", "3", dstIP.String()).Run()
	default:
		ping := "ping"
		if isSynology {
			ping = "/bin/ping"
		}
		cmd := exec.Command(ping, "-c", "1", "-W", "3", dstIP.String())
		if isSynology && os.Getuid() != 0 {
			// On DSM7 we run as non-root and need to pass
			// CAP_NET_RAW if our binary has it.
			setAmbientCapsRaw(cmd)
		}
		err = cmd.Run()
	}
	d := time.Since(t0)
	if err != nil {
		if d < time.Second/2 {
			// If it failed quicker than the 3 second
			// timeout we gave above (500 ms is a
			// reasonable threshold), then assume the ping
			// failed for problems finding/running
			// ping. We don't want to log if the host is
			// just down.
			ns.logf("exec ping of %v failed in %v: %v", dstIP, d, err)
		}
		return
	}
	if debugNetstack() {
		ns.logf("exec pinged %v in %v", dstIP, time.Since(t0))
	}
	if err := ns.tundev.InjectOutbound(pingResPkt); err != nil {
		ns.logf("InjectOutbound ping response: %v", err)
	}
}

// injectInbound is installed as a packet hook on the 'inbound' (from a
// WireGuard peer) path. Returning filter.Accept releases the packet to
// continue normally (typically being delivered to the host networking stack),
// whereas returning filter.DropSilently is done when netstack intercepts the
// packet and no further processing towards to host should be done.
func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
	if ns.ctx.Err() != nil {
		return filter.DropSilently
	}

	if !ns.shouldProcessInbound(p, t) {
		// Let the host network stack (if any) deal with it.
		return filter.Accept
	}

	destIP := p.Dst.Addr()

	// If this is an echo request and we're a subnet router, handle pings
	// ourselves instead of forwarding the packet on.
	pingIP, handlePing := ns.shouldHandlePing(p)
	if handlePing {
		var pong []byte // the reply to the ping, if our relayed ping works
		if destIP.Is4() {
			h := p.ICMP4Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		} else if destIP.Is6() {
			h := p.ICMP6Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		}
		go ns.userPing(pingIP, pong)
		return filter.DropSilently
	}

	var pn tcpip.NetworkProtocolNumber
	switch p.IPVersion {
	case 4:
		pn = header.IPv4ProtocolNumber
	case 6:
		pn = header.IPv6ProtocolNumber
	}
	if debugPackets {
		ns.logf("[v2] packet in (from %v): % x", p.Src, p.Buffer())
	}
	packetBuf := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(bytes.Clone(p.Buffer())),
	})
	ns.linkEP.InjectInbound(pn, packetBuf)
	packetBuf.DecRef()

	// We've now delivered this to netstack, so we're done.
	// Instead of returning a filter.Accept here (which would also
	// potentially deliver it to the host OS), and instead of
	// filter.Drop (which would log about rejected traffic),
	// instead return filter.DropSilently which just quietly stops
	// processing it in the tstun TUN wrapper.
	return filter.DropSilently
}

// shouldHandlePing returns whether or not netstack should handle an incoming
// ICMP echo request packet, and the IP address that should be pinged from this
// process. The IP address can be different from the destination in the packet
// if the destination is a 4via6 address.
func (ns *Impl) shouldHandlePing(p *packet.Parsed) (_ netip.Addr, ok bool) {
	if !p.IsEchoRequest() {
		return netip.Addr{}, false
	}

	destIP := p.Dst.Addr()

	// We need to handle pings for all 4via6 addresses, even if this
	// netstack instance normally isn't responsible for processing subnets.
	//
	// For example, on Linux, subnet router traffic could be handled via
	// tun+iptables rules for most packets, but we still need to handle
	// ICMP echo requests over 4via6 since the host networking stack
	// doesn't know what to do with a 4via6 address.
	//
	// shouldProcessInbound returns 'true' to say that we should process
	// all IPv6 packets with a destination address in the 'via' range, so
	// check before we check the "ProcessSubnets" boolean below.
	if viaRange.Contains(destIP) {
		// The input echo request was to a 4via6 address, which we cannot
		// simply ping as-is from this process. Translate the destination to an
		// IPv4 address, so that our relayed ping (in userPing) is pinging the
		// underlying destination IP.
		//
		// ICMPv4 and ICMPv6 are different protocols with different on-the-wire
		// representations, so normally you can't send an ICMPv6 message over
		// IPv4 and expect to get a useful result. However, in this specific
		// case things are safe because the 'userPing' function doesn't make
		// use of the input packet.
		return tsaddr.UnmapVia(destIP), true
	}

	// If we get here, we don't do anything unless this netstack instance
	// is responsible for processing subnet traffic.
	if !ns.ProcessSubnets {
		return netip.Addr{}, false
	}

	// For non-4via6 addresses, we don't handle pings if they're destined
	// for a Tailscale IP.
	if tsaddr.IsCoderIP(destIP) {
		return netip.Addr{}, false
	}

	// This netstack instance is processing subnet traffic, so handle the
	// ping ourselves.
	return destIP, true
}

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch s.Len() {
	case 4:
		s := s.As4()
		return netaddr.IPv4(s[0], s[1], s[2], s[3])
	case 16:
		s := s.As16()
		return netip.AddrFrom16(s).Unmap()
	}
	return netip.Addr{}
}

func (ns *Impl) acceptTCP(r *tcp.ForwarderRequest) {
	reqDetails := r.ID()
	if debugNetstack() {
		ns.logf("[v2] TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
	}
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	if !clientRemoteIP.IsValid() {
		ns.logf("invalid RemoteAddress in TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
		r.Complete(true) // sends a RST
		return
	}
	clientRemotePort := reqDetails.RemotePort
	clientRemoteAddrPort := netip.AddrPortFrom(clientRemoteIP, clientRemotePort)

	dialIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	isLocal := ns.isLocalIP(dialIP)

	dstAddrPort := netip.AddrPortFrom(dialIP, reqDetails.LocalPort)

	if viaRange.Contains(dialIP) {
		isLocal = false
		dialIP = tsaddr.UnmapVia(dialIP)
	}

	defer func() {
		if !isLocal {
			// if this is a subnet IP, we added this in before the TCP handshake
			// so netstack is happy TCP-handshaking as a subnet IP
			ns.removeSubnetAddress(dialIP)
		}
	}()

	var wq waiter.Queue

	// We can't actually create the endpoint or complete the inbound
	// request until we're sure that the connection can be handled by this
	// endpoint. This function sets up the TCP connection and should be
	// called immediately before a connection is handled.
	getConnOrReset := func(opts ...tcpip.SettableSocketOption) *gonet.TCPConn {
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			ns.logf("CreateEndpoint error for %s: %v", stringifyTEI(reqDetails), err)
			r.Complete(true) // sends a RST
			return nil
		}
		r.Complete(false)
		for _, opt := range opts {
			ep.SetSockOpt(opt)
		}
		// SetKeepAlive so that idle connections to peers that have forgotten about
		// the connection or gone completely offline eventually time out.
		// Applications might be setting this on a forwarded connection, but from
		// userspace we can not see those, so the best we can do is to always
		// perform them with conservative timing.
		// TODO(tailscale/tailscale#4522): Netstack defaults match the Linux
		// defaults, and results in a little over two hours before the socket would
		// be closed due to keepalive. A shorter default might be better, or seeking
		// a default from the host IP stack. This also might be a useful
		// user-tunable, as in userspace mode this can have broad implications such
		// as lingering connections to fork style daemons. On the other side of the
		// fence, the long duration timers are low impact values for battery powered
		// peers.
		ep.SocketOptions().SetKeepAlive(true)

		// The ForwarderRequest.CreateEndpoint above asynchronously
		// starts the TCP handshake. Note that the gonet.TCPConn
		// methods c.RemoteAddr() and c.LocalAddr() will return nil
		// until the handshake actually completes. But we have the
		// remote address in reqDetails instead, so we don't use
		// gonet.TCPConn.RemoteAddr. The byte copies in both
		// directions to/from the gonet.TCPConn in forwardTCP will
		// block until the TCP handshake is complete.
		return gonet.NewTCPConn(&wq, ep)
	}

	// DNS
	if reqDetails.LocalPort == 53 && dialIP == coderDNSIPv6 {
		c := getConnOrReset()
		if c == nil {
			return
		}
		go ns.dns.HandleTCPConn(c, netip.AddrPortFrom(clientRemoteIP, reqDetails.RemotePort))
		return
	}

	if ns.lb != nil {
		handler, opts := ns.lb.TCPHandlerForDst(clientRemoteAddrPort, dstAddrPort)
		if handler != nil {
			c := getConnOrReset(opts...) // will send a RST if it fails
			if c == nil {
				return
			}
			handler(c)
			return
		}
	}

	if ns.GetTCPHandlerForFlow != nil {
		handler, opts, ok := ns.GetTCPHandlerForFlow(clientRemoteAddrPort, dstAddrPort)
		if ok {
			if handler == nil {
				r.Complete(true)
				return
			}
			c := getConnOrReset(opts...) // will send a RST if it fails
			if c == nil {
				return
			}
			handler(c)
			return
		}
	}
	if isLocal {
		dialIP = netaddr.IPv4(127, 0, 0, 1)
	}
	dialAddr := netip.AddrPortFrom(dialIP, uint16(reqDetails.LocalPort))

	if !ns.forwardTCP(getConnOrReset, clientRemoteIP, &wq, dialAddr) {
		r.Complete(true) // sends a RST
	}
}

func (ns *Impl) forwardTCP(getClient func(...tcpip.SettableSocketOption) *gonet.TCPConn, clientRemoteIP netip.Addr, wq *waiter.Queue, dialAddr netip.AddrPort) (handled bool) {
	dialAddrStr := dialAddr.String()
	if debugNetstack() {
		ns.logf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			if debugNetstack() {
				ns.logf("[v2] netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
			}
		case <-done:
		}
		cancel()
	}()

	// Attempt to dial the outbound connection before we accept the inbound one.
	var stdDialer net.Dialer
	server, err := stdDialer.DialContext(ctx, "tcp", dialAddrStr)
	if err != nil {
		// Coder: Retry with loopback IPv6 if the dial was for 127.0.0.1.
		if dialAddr.Addr().Is4() && dialAddr.Addr().String() == "127.0.0.1" {
			ipv6DialAddr := netip.AddrPortFrom(netip.IPv6Loopback(), dialAddr.Port())
			server, err = stdDialer.DialContext(ctx, "tcp", ipv6DialAddr.String())
			if err == nil {
				if debugNetstack() {
					ns.logf("[coder] netstack: successful IPv4 loopback => IPv6 loopback redirect: original = %s, new = %s", dialAddrStr, ipv6DialAddr.String())
				}
				dialAddr = ipv6DialAddr
				dialAddrStr = ipv6DialAddr.String()
			} else {
				ns.logf("netstack: could not connect to local server at %s (or %s)", dialAddrStr, ipv6DialAddr.String(), err)
				return
			}
		} else {
			ns.logf("netstack: could not connect to local server at %s: %v", dialAddr.String(), err)
			return
		}
	}
	defer server.Close()

	// If we get here, either the getClient call below will succeed and
	// return something we can Close, or it will fail and will properly
	// respond to the client with a RST. Either way, the caller no longer
	// needs to clean up the client connection.
	handled = true

	// We dialed the connection; we can complete the client's TCP handshake.
	client := getClient()
	if client == nil {
		return
	}
	defer client.Close()

	backendLocalAddr := server.LocalAddr().(*net.TCPAddr)
	backendLocalIPPort := netaddr.Unmap(backendLocalAddr.AddrPort())
	ns.e.RegisterIPPortIdentity(backendLocalIPPort, clientRemoteIP)
	defer ns.e.UnregisterIPPortIdentity(backendLocalIPPort)
	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(server, client)
		connClosed <- err
	}()
	go func() {
		_, err := io.Copy(client, server)
		connClosed <- err
	}()
	err = <-connClosed
	if err != nil {
		ns.logf("proxy connection closed with error: %v", err)
	}
	ns.logf("[v2] netstack: forwarder connection to %s closed", dialAddrStr)
	return
}

func (ns *Impl) acceptUDP(r *udp.ForwarderRequest) {
	sess := r.ID()
	if debugNetstack() {
		ns.logf("[v2] UDP ForwarderRequest: %v", stringifyTEI(sess))
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("acceptUDP: could not create endpoint: %v", err)
		return
	}
	dstAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		ep.Close()
		return
	}
	srcAddr, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
	if !ok {
		ep.Close()
		return
	}

	// Handle magicDNS traffic (via UDP) here.
	if dst := dstAddr.Addr(); dst == coderDNSIPv6 {
		if dstAddr.Port() != 53 {
			ep.Close()
			return // Only MagicDNS traffic runs on the service IPs for now.
		}

		c := gonet.NewUDPConn(&wq, ep)
		go ns.handleMagicDNSUDP(srcAddr, c)
		return
	}

	if get := ns.GetUDPHandlerForFlow; get != nil {
		h, intercept := get(srcAddr, dstAddr)
		if intercept {
			if h == nil {
				ep.Close()
				return
			}
			go h(gonet.NewUDPConn(&wq, ep))
			return
		}
	}

	c := gonet.NewUDPConn(&wq, ep)
	go ns.forwardUDP(c, srcAddr, dstAddr)
}

func (ns *Impl) handleMagicDNSUDP(srcAddr netip.AddrPort, c *gonet.UDPConn) {
	// In practice, implementations are advised not to exceed 512 bytes
	// due to fragmenting. Just to be sure, we bump all the way to the MTU.
	var maxUDPReqSize = tstun.DefaultMTU()
	// Packets are being generated by the local host, so there should be
	// very, very little latency. 150ms was chosen as something of an upper
	// bound on resource usage, while hopefully still being long enough for
	// a heavily loaded system.
	const readDeadline = 150 * time.Millisecond

	defer c.Close()
	q := make([]byte, maxUDPReqSize)

	// libresolv from glibc is quite adamant that transmitting multiple DNS
	// requests down the same UDP socket is valid. To support this, we read
	// in a loop (with a tight deadline so we don't chew too many resources).
	//
	// See: https://github.com/bminor/glibc/blob/f7fbb99652eceb1b6b55e4be931649df5946497c/resolv/res_send.c#L995
	for {
		c.SetReadDeadline(time.Now().Add(readDeadline))
		n, _, err := c.ReadFrom(q)
		if err != nil {
			if oe, ok := err.(*net.OpError); !(ok && oe.Timeout()) {
				ns.logf("dns udp read: %v", err) // log non-timeout errors
			}
			return
		}
		resp, err := ns.dns.Query(context.Background(), q[:n], srcAddr)
		if err != nil {
			ns.logf("dns udp query: %v", err)
			return
		}
		c.Write(resp)
	}
}

// forwardUDP proxies between client (with addr clientAddr) and dstAddr.
//
// dstAddr may be either a local Tailscale IP, in which we case we proxy to
// 127.0.0.1, or any other IP (from an advertised subnet), in which case we
// proxy to it directly.
func (ns *Impl) forwardUDP(client *gonet.UDPConn, clientAddr, dstAddr netip.AddrPort) {
	port, srcPort := dstAddr.Port(), clientAddr.Port()
	if debugNetstack() {
		ns.logf("[v2] netstack: forwarding incoming UDP connection on port %v", port)
	}

	var backendListenAddr *net.UDPAddr
	var backendRemoteAddr *net.UDPAddr
	isLocal := ns.isLocalIP(dstAddr.Addr())
	if isLocal {
		backendRemoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(srcPort)}
	} else {
		if dstIP := dstAddr.Addr(); viaRange.Contains(dstIP) {
			dstAddr = netip.AddrPortFrom(tsaddr.UnmapVia(dstIP), dstAddr.Port())
		}
		backendRemoteAddr = net.UDPAddrFromAddrPort(dstAddr)
		if dstAddr.Addr().Is4() {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(srcPort)}
		} else {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("::"), Port: int(srcPort)}
		}
	}

	backendConn, err := net.ListenUDP("udp", backendListenAddr)
	if err != nil {
		ns.logf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp", backendListenAddr)
		if err != nil {
			ns.logf("netstack: could not create UDP socket, preventing forwarding to %v: %v", dstAddr, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)

	backendLocalIPPort := netip.AddrPortFrom(backendListenAddr.AddrPort().Addr().Unmap().WithZone(backendLocalAddr.Zone), backendLocalAddr.AddrPort().Port())
	if !backendLocalIPPort.IsValid() {
		ns.logf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}
	if isLocal {
		ns.e.RegisterIPPortIdentity(backendLocalIPPort, dstAddr.Addr())
	}
	ctx, cancel := context.WithCancel(context.Background())

	idleTimeout := 2 * time.Minute
	if port == 53 {
		// Make DNS packet copies time out much sooner.
		//
		// TODO(bradfitz): make DNS queries over UDP forwarding even
		// cheaper by adding an additional idleTimeout post-DNS-reply.
		// For instance, after the DNS response goes back out, then only
		// wait a few seconds (or zero, really)
		idleTimeout = 30 * time.Second
	}
	timer := time.AfterFunc(idleTimeout, func() {
		if isLocal {
			ns.e.UnregisterIPPortIdentity(backendLocalIPPort)
		}
		ns.logf("netstack: UDP session between %s and %s timed out", backendListenAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})
	extend := func() {
		timer.Reset(idleTimeout)
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-ns.ctx.Done():
		}
		client.Close()
		backendConn.Close()
	}()
	startPacketCopy(ctx, cancel, client, net.UDPAddrFromAddrPort(clientAddr), backendConn, ns.logf, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, ns.logf, extend)
	if isLocal {
		// Wait for the copies to be done before decrementing the
		// subnet address count to potentially remove the route.
		<-ctx.Done()
		ns.removeSubnetAddress(dstAddr.Addr())
	}
}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, logf logger.Logf, extend func()) {
	if debugNetstack() {
		logf("[v2] netstack: startPacketCopy to %v (%T) from %T", dstAddr, dst, src)
	}
	go func() {
		defer cancel() // tear down the other direction's copy
		pkt := make([]byte, maxUDPPacketSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, srcAddr, err := src.ReadFrom(pkt)
				if err != nil {
					if ctx.Err() == nil {
						logf("read packet from %s failed: %v", srcAddr, err)
					}
					return
				}
				_, err = dst.WriteTo(pkt[:n], dstAddr)
				if err != nil {
					if ctx.Err() == nil {
						logf("write packet to %s failed: %v", dstAddr, err)
					}
					return
				}
				if debugNetstack() {
					logf("[v2] wrote UDP packet %s -> %s", srcAddr, dstAddr)
				}
				extend()
			}
		}
	}()
}

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	if addr, ok := netip.AddrFromSlice(a.AsSlice()); ok {
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}
