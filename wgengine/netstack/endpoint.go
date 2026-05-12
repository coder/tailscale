// based on https://github.com/google/gvisor/blob/74f22885dc45e2866985fe7179103e1000382415/pkg/tcpip/link/channel/channel.go
//
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modifications from original source are Copyright 2024 Tailscale Inc & AUTHORS

package netstack

import (
	"context"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type queue struct {
	// c is the outbound packet channel.
	c  chan *stack.PacketBuffer
	mu sync.RWMutex
	// +checklocks:mu
	closed bool

	closedChOnce sync.Once
	closedCh     chan struct{}
}

func (q *queue) Close() {
	// This unblocks any calls to Write() which might be holding the mu.
	q.closedChOnce.Do(func() {
		close(q.closedCh)
	})

	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	close(q.c)
	q.closed = true
}

func (q *queue) Read() *stack.PacketBuffer {
	select {
	case p := <-q.c:
		return p
	default:
		return nil
	}
}

func (q *queue) ReadContext(ctx context.Context) *stack.PacketBuffer {
	select {
	case pkt := <-q.c:
		return pkt
	case <-ctx.Done():
		return nil
	}
}

func (q *queue) Write(pkt *stack.PacketBuffer) tcpip.Error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return &tcpip.ErrClosedForSend{}
	}
	select {
	case q.c <- pkt.IncRef():
		return nil
	case <-q.closedCh:
		pkt.DecRef()
		return &tcpip.ErrClosedForSend{}
	}
}

func (q *queue) Num() int {
	return len(q.c)
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.  It is based on gVisor
// channel.Endpoint, however when the channel is full, it blocks writes until
// there is space in the channel or until the Endpoint is closed.  The gVisor
// version dropped packets if the channel is full.  This limits TCP throughput
// as dropped packets need to be retransmitted and are interpreted as a
// congestion event, causing the TCP sender to decrease the congestion window.
// Much better to apply back-pressure to the TCP stack at the Endpoint.
type Endpoint struct {
	mtu                uint32
	linkAddr           tcpip.LinkAddress
	LinkEPCapabilities stack.LinkEndpointCapabilities
	SupportedGSOKind   stack.SupportedGSO

	mu sync.RWMutex
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher

	// Outbound packet queue.
	q *queue
}

// NewEndpoint creates a new channel endpoint.
func NewEndpoint(size int, mtu uint32, linkAddr tcpip.LinkAddress) *Endpoint {
	return &Endpoint{
		q: &queue{
			c:        make(chan *stack.PacketBuffer, size),
			closedCh: make(chan struct{}),
		},
		mtu:      mtu,
		linkAddr: linkAddr,
	}
}

func (*Endpoint) SetLinkAddress(tcpip.LinkAddress) {
	panic("not implemented")
}

func (*Endpoint) SetMTU(uint32) {
	panic("not implemented")
}

func (*Endpoint) SetOnCloseAction(func()) {
	panic("not implemented")
}

// Close closes e. Further packet injections will return an error, and all pending
// packets are discarded. Close may be called concurrently with WritePackets.
func (e *Endpoint) Close() {
	e.q.Close()
	e.Drain()
}

// Read does non-blocking read one packet from the outbound packet queue.
func (e *Endpoint) Read() *stack.PacketBuffer {
	return e.q.Read()
}

// ReadContext does blocking read for one packet from the outbound packet queue.
// It can be cancelled by ctx, and in this case, it returns nil.
func (e *Endpoint) ReadContext(ctx context.Context) *stack.PacketBuffer {
	return e.q.ReadContext(ctx)
}

// Drain removes all outbound packets from the channel and counts them.
func (e *Endpoint) Drain() int {
	c := 0
	for pkt := e.Read(); pkt != nil; pkt = e.Read() {
		pkt.DecRef()
		c++
	}
	return c
}

// NumQueued returns the number of packet queued for outbound.
func (e *Endpoint) NumQueued() int {
	return e.q.Num()
}

// InjectInbound injects an inbound packet. If the endpoint is not attached, the
// packet is not delivered.
func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEPCapabilities
}

// GSOMaxSize implements stack.GSOEndpoint.
func (*Endpoint) GSOMaxSize() uint32 {
	return 1 << 15
}

// SupportedGSO implements stack.GSOEndpoint.
func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	return e.SupportedGSOKind
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if err := e.q.Write(pkt); err != nil {
			return n, err
		}
		n++
	}

	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*Endpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (*Endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (*Endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }
