// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package wgengine

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/capture"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// ErrWatchdogTimeout is returned when a watchdog configured with a timeout
// callback times out.
var ErrWatchdogTimeout = errors.New("wgengine watchdog timeout")

// NewWatchdog wraps an Engine and makes sure that all methods complete
// within a reasonable amount of time.
//
// If they do not, the watchdog crashes the process.
func NewWatchdog(e Engine) Engine {
	if envknob.Bool("TS_DEBUG_DISABLE_WATCHDOG") {
		return e
	}
	return newWatchdog(e, nil, false)
}

// NewWatchdogWithTimeoutCallback wraps an Engine and synchronously calls
// callback when the first operation times out. The callback must not block or
// call methods on the returned Engine.
// Unlike NewWatchdog, this does not terminate the process on timeout.
func NewWatchdogWithTimeoutCallback(e Engine, callback func(operation string)) Engine {
	if envknob.Bool("TS_DEBUG_DISABLE_WATCHDOG") {
		return e
	}
	return newWatchdog(e, callback, true)
}

func newWatchdog(e Engine, callback func(operation string), recoverOnTimeout bool) *watchdogEngine {
	return &watchdogEngine{
		wrap:             e,
		logf:             log.Printf,
		fatalf:           log.Fatalf,
		timeoutCallback:  callback,
		recoverOnTimeout: recoverOnTimeout,
		maxWait:          45 * time.Second,
		poisonedDone:     make(chan struct{}),
		closeDone:        make(chan struct{}),
		wrappedWaitDone:  make(chan struct{}),
		inFlight:         make(map[inFlightKey]time.Time),
	}
}

type inFlightKey struct {
	op  string
	ctr uint64
}

type whoIsIPPortResult struct {
	tsIP netip.Addr
	ok   bool
}

type peerForIPResult struct {
	peer PeerForIP
	ok   bool
}

func watchdogValue[T any](e *watchdogEngine, name string, fn func() T) (T, bool) {
	var zero T
	resultCh := make(chan T, 1)
	err := e.watchdogErr(name, func() error {
		resultCh <- fn()
		return nil
	})
	if err != nil {
		return zero, false
	}
	return <-resultCh, true
}

type watchdogEngine struct {
	wrap    Engine
	logf    func(format string, args ...any)
	fatalf  func(format string, args ...any)
	maxWait time.Duration

	timeoutCallback  func(operation string)
	recoverOnTimeout bool
	poisoned         atomic.Bool
	poisonedDone     chan struct{}
	closeStarted     atomic.Bool
	closeDone        chan struct{}
	waitStarted      atomic.Bool
	wrappedWaitDone  chan struct{}

	// Track the start time(s) of in-flight operations
	inFlightMu  sync.Mutex
	inFlight    map[inFlightKey]time.Time
	inFlightCtr uint64
}

func (e *watchdogEngine) watchdogErr(name string, fn func() error) error {
	err, _ := e.watchdogErrStarted(name, fn)
	return err
}

func (e *watchdogEngine) watchdogErrStarted(name string, fn func() error) (error, bool) {
	if e.poisoned.Load() {
		if e.recoverOnTimeout {
			<-e.poisonedDone
			return ErrWatchdogTimeout, false
		}
		return nil, false
	}

	// Track all in-flight operations so we can print more useful error
	// messages on watchdog failure
	e.inFlightMu.Lock()
	key := inFlightKey{
		op:  name,
		ctr: e.inFlightCtr,
	}
	e.inFlightCtr++
	e.inFlight[key] = time.Now()
	e.inFlightMu.Unlock()

	defer func() {
		e.inFlightMu.Lock()
		defer e.inFlightMu.Unlock()
		delete(e.inFlight, key)
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- fn()
	}()
	t := time.NewTimer(e.maxWait)
	var poisonedDone <-chan struct{}
	if e.recoverOnTimeout {
		poisonedDone = e.poisonedDone
	}
	select {
	case err := <-errCh:
		t.Stop()
		if e.recoverOnTimeout && e.poisoned.Load() {
			<-e.poisonedDone
			return ErrWatchdogTimeout, true
		}
		return err, true
	case <-poisonedDone:
		t.Stop()
		return ErrWatchdogTimeout, true
	case <-t.C:
		return e.watchdogTimeout(name), true
	}
}

func (e *watchdogEngine) watchdogTimeout(name string) error {
	firstTimeout := e.poison(name)
	buf := new(strings.Builder)
	pprof.Lookup("goroutine").WriteTo(buf, 1)
	e.logf("wgengine watchdog stacks:\n%s", buf.String())

	// Collect the list of in-flight operations for debugging.
	var (
		b   []byte
		now = time.Now()
	)
	e.inFlightMu.Lock()
	for k, t := range e.inFlight {
		dur := now.Sub(t).Round(time.Millisecond)
		b = fmt.Appendf(b, "in-flight[%d]: name=%s duration=%v start=%s\n", k.ctr, k.op, dur, t.Format(time.RFC3339Nano))
	}
	e.inFlightMu.Unlock()

	// Print everything as a single string to avoid log
	// rate limits.
	e.logf("wgengine watchdog in-flight:\n%s", b)
	if firstTimeout && !e.recoverOnTimeout && e.fatalf != nil {
		e.fatalf("wgengine: watchdog timeout on %s", name)
	}
	if e.recoverOnTimeout {
		<-e.poisonedDone
		return ErrWatchdogTimeout
	}
	return nil
}

func (e *watchdogEngine) poison(operation string) bool {
	if !e.poisoned.CompareAndSwap(false, true) {
		return false
	}
	defer close(e.poisonedDone)
	if e.recoverOnTimeout && e.timeoutCallback != nil {
		e.timeoutCallback(operation)
	}
	return true
}

func (e *watchdogEngine) watchdog(name string, fn func()) {
	e.watchdogErr(name, func() error {
		fn()
		return nil
	})
}

func (e *watchdogEngine) Reconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *dns.Config, debug *tailcfg.Debug) error {
	return e.watchdogErr("Reconfig", func() error { return e.wrap.Reconfig(cfg, routerCfg, dnsCfg, debug) })
}
func (e *watchdogEngine) GetFilter() *filter.Filter {
	if e.poisoned.Load() {
		return nil
	}
	return e.wrap.GetFilter()
}
func (e *watchdogEngine) SetFilter(filt *filter.Filter) {
	e.watchdog("SetFilter", func() { e.wrap.SetFilter(filt) })
}
func (e *watchdogEngine) SetStatusCallback(cb StatusCallback) {
	if cb == nil {
		e.watchdog("SetStatusCallback", func() { e.wrap.SetStatusCallback(nil) })
		return
	}
	e.watchdog("SetStatusCallback", func() {
		e.wrap.SetStatusCallback(func(status *Status, err error) {
			if !e.poisoned.Load() {
				cb(status, err)
			}
		})
	})
}
func (e *watchdogEngine) UpdateStatus(sb *ipnstate.StatusBuilder) {
	e.watchdog("UpdateStatus", func() { e.wrap.UpdateStatus(sb) })
}
func (e *watchdogEngine) SetNetInfoCallback(cb NetInfoCallback) {
	if cb == nil {
		e.watchdog("SetNetInfoCallback", func() { e.wrap.SetNetInfoCallback(nil) })
		return
	}
	e.watchdog("SetNetInfoCallback", func() {
		e.wrap.SetNetInfoCallback(func(netInfo *tailcfg.NetInfo) {
			if !e.poisoned.Load() {
				cb(netInfo)
			}
		})
	})
}
func (e *watchdogEngine) RequestStatus() {
	e.watchdog("RequestStatus", func() { e.wrap.RequestStatus() })
}
func (e *watchdogEngine) LinkChange(isExpensive bool) {
	e.watchdog("LinkChange", func() { e.wrap.LinkChange(isExpensive) })
}
func (e *watchdogEngine) SetDERPMap(m *tailcfg.DERPMap) {
	e.watchdog("SetDERPMap", func() { e.wrap.SetDERPMap(m) })
}
func (e *watchdogEngine) SetNetworkMap(nm *netmap.NetworkMap) {
	e.watchdog("SetNetworkMap", func() { e.wrap.SetNetworkMap(nm) })
}
func (e *watchdogEngine) AddNetworkMapCallback(callback NetworkMapCallback) func() {
	resultCh := make(chan func(), 1)
	err, started := e.watchdogErrStarted("AddNetworkMapCallback", func() error {
		resultCh <- e.wrap.AddNetworkMapCallback(func(networkMap *netmap.NetworkMap) {
			if !e.poisoned.Load() {
				callback(networkMap)
			}
		})
		return nil
	})
	if err != nil {
		if started {
			go func() {
				if remove := <-resultCh; remove != nil {
					remove()
				}
			}()
		}
		return func() {}
	}
	remove := <-resultCh
	if remove == nil {
		return func() {}
	}
	if e.poisoned.Load() {
		go remove()
		return func() {}
	}
	var removeOnce sync.Once
	return func() {
		removeOnce.Do(func() {
			_, started := e.watchdogErrStarted("RemoveNetworkMapCallback", func() error {
				remove()
				return nil
			})
			if !started {
				go remove()
			}
		})
	}
}
func (e *watchdogEngine) DiscoPublicKey() key.DiscoPublic {
	k, ok := watchdogValue(e, "DiscoPublicKey", func() key.DiscoPublic {
		return e.wrap.DiscoPublicKey()
	})
	if !ok {
		return key.DiscoPublic{}
	}
	return k
}
func (e *watchdogEngine) Ping(ip netip.Addr, pingType tailcfg.PingType, cb func(*ipnstate.PingResult)) {
	if cb == nil {
		e.watchdog("Ping", func() { e.wrap.Ping(ip, pingType, nil) })
		return
	}
	e.watchdog("Ping", func() {
		e.wrap.Ping(ip, pingType, func(result *ipnstate.PingResult) {
			if !e.poisoned.Load() {
				cb(result)
			}
		})
	})
}
func (e *watchdogEngine) RegisterIPPortIdentity(ipp netip.AddrPort, tsIP netip.Addr) {
	e.watchdog("RegisterIPPortIdentity", func() { e.wrap.RegisterIPPortIdentity(ipp, tsIP) })
}
func (e *watchdogEngine) UnregisterIPPortIdentity(ipp netip.AddrPort) {
	e.watchdog("UnregisterIPPortIdentity", func() { e.wrap.UnregisterIPPortIdentity(ipp) })
}
func (e *watchdogEngine) WhoIsIPPort(ipp netip.AddrPort) (netip.Addr, bool) {
	result, ok := watchdogValue(e, "WhoIsIPPort", func() whoIsIPPortResult {
		tsIP, ok := e.wrap.WhoIsIPPort(ipp)
		return whoIsIPPortResult{tsIP: tsIP, ok: ok}
	})
	if !ok {
		return netip.Addr{}, false
	}
	return result.tsIP, result.ok
}
func (e *watchdogEngine) Close() {
	if e.closeStarted.CompareAndSwap(false, true) {
		go func() {
			e.wrap.Close()
			close(e.closeDone)
		}()
	}
	if e.poisoned.Load() {
		return
	}
	t := time.NewTimer(e.maxWait)
	select {
	case <-e.closeDone:
		t.Stop()
	case <-e.poisonedDone:
		t.Stop()
	case <-t.C:
		_ = e.watchdogTimeout("Close")
	}
}
func (e *watchdogEngine) PeerForIP(ip netip.Addr) (PeerForIP, bool) {
	result, ok := watchdogValue(e, "PeerForIP", func() peerForIPResult {
		peer, ok := e.wrap.PeerForIP(ip)
		return peerForIPResult{peer: peer, ok: ok}
	})
	if !ok {
		return PeerForIP{}, false
	}
	return result.peer, result.ok
}

func (e *watchdogEngine) Wait() {
	if e.poisoned.Load() {
		return
	}
	if e.waitStarted.CompareAndSwap(false, true) {
		go func() {
			e.wrap.Wait()
			close(e.wrappedWaitDone)
		}()
	}
	select {
	case <-e.wrappedWaitDone:
	case <-e.poisonedDone:
	}
}

func (e *watchdogEngine) InstallCaptureHook(cb capture.Callback) {
	if e.poisoned.Load() {
		return
	}
	if cb == nil {
		e.wrap.InstallCaptureHook(nil)
		return
	}
	e.wrap.InstallCaptureHook(func(path capture.Path, at time.Time, data []byte, meta packet.CaptureMeta) {
		if !e.poisoned.Load() {
			cb(path, at, data, meta)
		}
	})
}
