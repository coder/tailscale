// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

const watchdogTestTimeout = time.Second

type watchdogTestEngine struct {
	Engine

	reconfigCalls   atomic.Int32
	reconfigEntered chan<- struct{}
	reconfigRelease <-chan struct{}
	reconfigErr     error

	closeCalls   atomic.Int32
	closeEntered chan<- struct{}
	closeRelease <-chan struct{}

	waitEntered chan<- struct{}
	waitRelease <-chan struct{}

	peerEntered chan<- struct{}
	peerRelease <-chan struct{}
	peerResult  PeerForIP
	peerOK      bool

	pingCallback chan<- func(*ipnstate.PingResult)

	addNetworkMapCallbackCalls    atomic.Int32
	removeNetworkMapCallbackCalls atomic.Int32
	addNetworkMapCallbackEntered  chan<- struct{}
	addNetworkMapCallbackRelease  <-chan struct{}
	removeNetworkMapCallbackDone  chan<- struct{}
}

func (e *watchdogTestEngine) Reconfig(*wgcfg.Config, *router.Config, *dns.Config, *tailcfg.Debug) error {
	e.reconfigCalls.Add(1)
	if e.reconfigEntered != nil {
		e.reconfigEntered <- struct{}{}
	}
	if e.reconfigRelease != nil {
		<-e.reconfigRelease
	}
	return e.reconfigErr
}

func (e *watchdogTestEngine) Close() {
	e.closeCalls.Add(1)
	if e.closeEntered != nil {
		e.closeEntered <- struct{}{}
	}
	if e.closeRelease != nil {
		<-e.closeRelease
	}
}

func (e *watchdogTestEngine) Wait() {
	if e.waitEntered != nil {
		e.waitEntered <- struct{}{}
	}
	if e.waitRelease != nil {
		<-e.waitRelease
	}
}

func (e *watchdogTestEngine) PeerForIP(netip.Addr) (PeerForIP, bool) {
	if e.peerEntered != nil {
		e.peerEntered <- struct{}{}
	}
	if e.peerRelease != nil {
		<-e.peerRelease
	}
	return e.peerResult, e.peerOK
}

func (e *watchdogTestEngine) Ping(_ netip.Addr, _ tailcfg.PingType, callback func(*ipnstate.PingResult)) {
	if e.pingCallback != nil {
		e.pingCallback <- callback
	}
}

func (e *watchdogTestEngine) AddNetworkMapCallback(NetworkMapCallback) func() {
	e.addNetworkMapCallbackCalls.Add(1)
	if e.addNetworkMapCallbackEntered != nil {
		e.addNetworkMapCallbackEntered <- struct{}{}
	}
	if e.addNetworkMapCallbackRelease != nil {
		<-e.addNetworkMapCallbackRelease
	}
	return func() {
		e.removeNetworkMapCallbackCalls.Add(1)
		if e.removeNetworkMapCallbackDone != nil {
			e.removeNetworkMapCallbackDone <- struct{}{}
		}
	}
}

func newWatchdogTest(t *testing.T, e Engine, callback func(string)) *watchdogEngine {
	t.Helper()
	wrapped := NewWatchdogWithTimeoutCallback(e, callback)
	wd := wrapped.(*watchdogEngine)
	wd.maxWait = 20 * time.Millisecond
	wd.logf = func(string, ...any) {}
	return wd
}

func waitWatchdogTest(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(watchdogTestTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestWatchdog(t *testing.T) {
	t.Parallel()

	var maxWaitMultiple time.Duration = 1
	if runtime.GOOS == "darwin" {
		// Work around slow close syscalls on Big Sur with content filter Network Extensions installed.
		// See https://github.com/tailscale/tailscale/issues/1598.
		maxWaitMultiple = 15
	}

	t.Run("default watchdog does not fire", func(t *testing.T) {
		t.Parallel()
		e, err := NewFakeUserspaceEngine(t.Logf, 0)
		if err != nil {
			t.Fatal(err)
		}

		e = NewWatchdog(e)
		e.(*watchdogEngine).maxWait = maxWaitMultiple * 150 * time.Millisecond
		e.(*watchdogEngine).logf = t.Logf
		e.(*watchdogEngine).fatalf = t.Fatalf

		e.RequestStatus()
		e.RequestStatus()
		e.RequestStatus()
		e.Close()
	})
}

func TestWatchdogDefaultTimeoutCallsFatal(t *testing.T) {
	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
	}
	wd := NewWatchdog(e).(*watchdogEngine)
	wd.maxWait = 20 * time.Millisecond
	wd.logf = func(string, ...any) {}
	fatalCalled := make(chan struct{}, 1)
	wd.fatalf = func(string, ...any) {
		fatalCalled <- struct{}{}
	}

	result := make(chan error, 1)
	go func() {
		result <- wd.Reconfig(nil, nil, nil, nil)
	}()
	waitWatchdogTest(t, reconfigEntered, "default Reconfig")
	waitWatchdogTest(t, fatalCalled, "default fatal hook")
	close(reconfigRelease)

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("default watchdog Reconfig error = %v, want nil", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for default Reconfig")
	}
}

func TestWatchdogDefaultTimeoutExitsProcess(t *testing.T) {
	if os.Getenv("TS_WATCHDOG_FATAL_TEST_CHILD") == "1" {
		envknob.Setenv("TS_DEBUG_DISABLE_WATCHDOG", "")
		e := &watchdogTestEngine{
			reconfigRelease: make(chan struct{}),
		}
		wd := NewWatchdog(e).(*watchdogEngine)
		wd.maxWait = 20 * time.Millisecond
		wd.logf = func(string, ...any) {}
		_ = wd.Reconfig(nil, nil, nil, nil)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWatchdogDefaultTimeoutExitsProcess$")
	cmd.Env = append(os.Environ(), "TS_WATCHDOG_FATAL_TEST_CHILD=1")
	output, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("watchdog child error = %v, want process exit; output: %s", err, output)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("watchdog child exit code = %d, want 1; output: %s", exitErr.ExitCode(), output)
	}
	if !strings.Contains(string(output), "wgengine: watchdog timeout on Reconfig") {
		t.Fatalf("watchdog child output missing fatal timeout: %s", output)
	}
}

func TestWatchdogDisabledLeavesHungOperationRunning(t *testing.T) {
	oldValue, hadValue := os.LookupEnv("TS_DEBUG_DISABLE_WATCHDOG")
	envknob.Setenv("TS_DEBUG_DISABLE_WATCHDOG", "true")
	t.Cleanup(func() {
		if hadValue {
			envknob.Setenv("TS_DEBUG_DISABLE_WATCHDOG", oldValue)
			return
		}
		envknob.Setenv("TS_DEBUG_DISABLE_WATCHDOG", "")
	})

	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
	}
	wrapped := NewWatchdog(e)
	if wrapped != e {
		t.Fatal("disabled watchdog wrapped the engine")
	}

	result := make(chan error, 1)
	go func() {
		result <- wrapped.Reconfig(nil, nil, nil, nil)
	}()
	waitWatchdogTest(t, reconfigEntered, "disabled Reconfig")
	select {
	case err := <-result:
		t.Fatalf("hung operation unexpectedly returned: %v", err)
	default:
	}

	close(reconfigRelease)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("disabled watchdog Reconfig error = %v, want nil", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for disabled Reconfig")
	}
}

func TestWatchdogTimeoutCallback(t *testing.T) {
	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	callbackCalled := make(chan string, 1)
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
	}
	wd := newWatchdogTest(t, e, func(operation string) {
		callbackCalled <- operation
	})
	fatalCalled := make(chan struct{}, 1)
	wd.fatalf = func(string, ...any) {
		fatalCalled <- struct{}{}
	}

	result := make(chan error, 1)
	go func() {
		result <- wd.Reconfig(nil, nil, nil, nil)
	}()
	waitWatchdogTest(t, reconfigEntered, "callback Reconfig")

	select {
	case err := <-result:
		if err != ErrWatchdogTimeout {
			t.Fatalf("callback Reconfig error = %v, want ErrWatchdogTimeout", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for callback Reconfig")
	}
	select {
	case operation := <-callbackCalled:
		if operation != "Reconfig" {
			t.Fatalf("timeout callback operation = %q, want Reconfig", operation)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for timeout callback")
	}
	select {
	case <-fatalCalled:
		t.Fatal("callback watchdog called fatal hook")
	default:
	}
	close(reconfigRelease)
}

func TestWatchdogTimeoutCallbackOnceAndPoisonedOperations(t *testing.T) {
	const operationCount = 3
	reconfigEntered := make(chan struct{}, operationCount)
	reconfigRelease := make(chan struct{})
	callbackCalled := make(chan string, operationCount)
	var callbackCount atomic.Int32
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
	}
	wd := newWatchdogTest(t, e, func(operation string) {
		callbackCount.Add(1)
		callbackCalled <- operation
	})

	results := make([]chan error, operationCount)
	for i := range results {
		results[i] = make(chan error, 1)
		go func(result chan<- error) {
			result <- wd.Reconfig(nil, nil, nil, nil)
		}(results[i])
	}
	for range operationCount {
		waitWatchdogTest(t, reconfigEntered, "concurrent Reconfig")
	}
	select {
	case <-callbackCalled:
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for first timeout callback")
	}

	callsBefore := e.reconfigCalls.Load()
	if err := wd.Reconfig(nil, nil, nil, nil); err != ErrWatchdogTimeout {
		t.Fatalf("poisoned Reconfig error = %v, want ErrWatchdogTimeout", err)
	}
	if callsAfter := e.reconfigCalls.Load(); callsAfter != callsBefore {
		t.Fatalf("poisoned Reconfig called underlying engine, calls = %d, want %d", callsAfter, callsBefore)
	}

	close(reconfigRelease)
	for i, result := range results {
		select {
		case err := <-result:
			if err != ErrWatchdogTimeout {
				t.Fatalf("concurrent Reconfig %d error = %v, want ErrWatchdogTimeout", i, err)
			}
		case <-time.After(watchdogTestTimeout):
			t.Fatalf("timed out waiting for concurrent Reconfig %d", i)
		}
	}
	if got := callbackCount.Load(); got != 1 {
		t.Fatalf("timeout callback count = %d, want 1", got)
	}
}

func TestWatchdogPoisonedNetworkMapCallbackRemover(t *testing.T) {
	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	result := make(chan error, 1)
	go func() {
		result <- wd.Reconfig(nil, nil, nil, nil)
	}()
	waitWatchdogTest(t, reconfigEntered, "poisoning Reconfig")
	select {
	case err := <-result:
		if err != ErrWatchdogTimeout {
			t.Fatalf("poisoning Reconfig error = %v, want ErrWatchdogTimeout", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for poisoning Reconfig")
	}

	addCalls := e.addNetworkMapCallbackCalls.Load()
	remove := wd.AddNetworkMapCallback(nil)
	if remove == nil {
		t.Fatal("poisoned AddNetworkMapCallback returned nil remover")
	}
	remove()
	remove()
	if got := e.addNetworkMapCallbackCalls.Load(); got != addCalls {
		t.Fatalf("poisoned AddNetworkMapCallback calls = %d, want %d", got, addCalls)
	}
	if got := e.removeNetworkMapCallbackCalls.Load(); got != 0 {
		t.Fatalf("poisoned remover called underlying engine %d times, want 0", got)
	}
	close(reconfigRelease)
}

func TestWatchdogPoisonedCloseReturnsPromptly(t *testing.T) {
	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	closeEntered := make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
		closeEntered:    closeEntered,
		closeRelease:    closeRelease,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	result := make(chan error, 1)
	go func() {
		result <- wd.Reconfig(nil, nil, nil, nil)
	}()
	waitWatchdogTest(t, reconfigEntered, "poisoning Reconfig")
	select {
	case err := <-result:
		if err != ErrWatchdogTimeout {
			t.Fatalf("poisoning Reconfig error = %v, want ErrWatchdogTimeout", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for poisoning Reconfig")
	}
	close(reconfigRelease)

	closeDone := make(chan struct{})
	go func() {
		wd.Close()
		close(closeDone)
	}()
	waitWatchdogTest(t, closeDone, "poisoned Close return")
	waitWatchdogTest(t, closeEntered, "underlying Close")
	if got := e.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", got)
	}

	waitDone := make(chan struct{})
	go func() {
		wd.Wait()
		close(waitDone)
	}()
	waitWatchdogTest(t, waitDone, "poisoned Wait return")
	wd.Close()
	if got := e.closeCalls.Load(); got != 1 {
		t.Fatalf("underlying Close calls after second Close = %d, want 1", got)
	}
	close(closeRelease)
}

func TestWatchdogTimedOutCloseAllowsSecondClose(t *testing.T) {
	closeEntered := make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	e := &watchdogTestEngine{
		closeEntered: closeEntered,
		closeRelease: closeRelease,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	firstDone := make(chan struct{})
	go func() {
		wd.Close()
		close(firstDone)
	}()
	waitWatchdogTest(t, closeEntered, "timed-out underlying Close")
	waitWatchdogTest(t, firstDone, "timed-out Close return")

	secondDone := make(chan struct{})
	go func() {
		wd.Close()
		close(secondDone)
	}()
	waitWatchdogTest(t, secondDone, "second poisoned Close return")
	close(closeRelease)
}

func TestWatchdogTimedOutValueWorkerReturnsZero(t *testing.T) {
	peerEntered := make(chan struct{}, 1)
	peerRelease := make(chan struct{})
	e := &watchdogTestEngine{
		peerEntered: peerEntered,
		peerRelease: peerRelease,
		peerResult:  PeerForIP{IsSelf: true},
		peerOK:      true,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	result := make(chan struct {
		peer PeerForIP
		ok   bool
	}, 1)
	go func() {
		peer, ok := wd.PeerForIP(netip.Addr{})
		result <- struct {
			peer PeerForIP
			ok   bool
		}{peer: peer, ok: ok}
	}()
	waitWatchdogTest(t, peerEntered, "timed-out value operation")

	select {
	case got := <-result:
		if got.ok || got.peer.IsSelf {
			t.Fatalf("timed-out value operation result = (%+v, %v), want zero", got.peer, got.ok)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for value operation")
	}
	close(peerRelease)
}

func TestWatchdogInFlightWaitReturnsAfterPoison(t *testing.T) {
	waitEntered := make(chan struct{}, 1)
	waitRelease := make(chan struct{})
	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	e := &watchdogTestEngine{
		waitEntered:     waitEntered,
		waitRelease:     waitRelease,
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	waitDone := make(chan struct{})
	go func() {
		wd.Wait()
		close(waitDone)
	}()
	waitWatchdogTest(t, waitEntered, "underlying Wait")

	reconfigDone := make(chan error, 1)
	go func() {
		reconfigDone <- wd.Reconfig(nil, nil, nil, nil)
	}()
	waitWatchdogTest(t, reconfigEntered, "poisoning Reconfig")
	select {
	case err := <-reconfigDone:
		if err != ErrWatchdogTimeout {
			t.Fatalf("poisoning Reconfig error = %v, want ErrWatchdogTimeout", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for poisoning Reconfig")
	}
	waitWatchdogTest(t, waitDone, "in-flight Wait return")
	close(reconfigRelease)
	close(waitRelease)
}

func TestWatchdogRemovesCallbackThatCompletesAfterTimeout(t *testing.T) {
	addEntered := make(chan struct{}, 1)
	addRelease := make(chan struct{})
	removeDone := make(chan struct{}, 1)
	e := &watchdogTestEngine{
		addNetworkMapCallbackEntered: addEntered,
		addNetworkMapCallbackRelease: addRelease,
		removeNetworkMapCallbackDone: removeDone,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	addDone := make(chan func(), 1)
	go func() {
		addDone <- wd.AddNetworkMapCallback(func(*netmap.NetworkMap) {})
	}()
	waitWatchdogTest(t, addEntered, "callback registration")
	var remove func()
	select {
	case remove = <-addDone:
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for callback registration timeout")
	}
	remove()
	close(addRelease)
	waitWatchdogTest(t, removeDone, "late callback removal")
}

func TestWatchdogPoisonWakesConcurrentOperations(t *testing.T) {
	reconfigEntered := make(chan struct{}, 1)
	reconfigRelease := make(chan struct{})
	peerEntered := make(chan struct{}, 1)
	peerRelease := make(chan struct{})
	e := &watchdogTestEngine{
		reconfigEntered: reconfigEntered,
		reconfigRelease: reconfigRelease,
		peerEntered:     peerEntered,
		peerRelease:     peerRelease,
		peerResult:      PeerForIP{IsSelf: true},
		peerOK:          true,
	}
	wd := newWatchdogTest(t, e, func(string) {})
	wd.maxWait = time.Hour

	reconfigDone := make(chan error, 1)
	go func() {
		reconfigDone <- wd.Reconfig(nil, nil, nil, nil)
	}()
	peerDone := make(chan struct {
		peer PeerForIP
		ok   bool
	}, 1)
	go func() {
		peer, ok := wd.PeerForIP(netip.Addr{})
		peerDone <- struct {
			peer PeerForIP
			ok   bool
		}{peer: peer, ok: ok}
	}()
	waitWatchdogTest(t, reconfigEntered, "concurrent Reconfig")
	waitWatchdogTest(t, peerEntered, "concurrent PeerForIP")

	if !wd.poison("test") {
		t.Fatal("failed to poison healthy watchdog")
	}
	select {
	case err := <-reconfigDone:
		if err != ErrWatchdogTimeout {
			t.Fatalf("concurrent Reconfig error = %v, want ErrWatchdogTimeout", err)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for concurrent Reconfig")
	}
	select {
	case got := <-peerDone:
		if got.ok || got.peer.IsSelf {
			t.Fatalf("concurrent PeerForIP result = (%+v, %v), want zero", got.peer, got.ok)
		}
	case <-time.After(watchdogTestTimeout):
		t.Fatal("timed out waiting for concurrent PeerForIP")
	}
	close(reconfigRelease)
	close(peerRelease)
}

func TestWatchdogQuarantinesCallbackAfterPoison(t *testing.T) {
	pingCallback := make(chan func(*ipnstate.PingResult), 1)
	callbackCalled := make(chan struct{}, 1)
	e := &watchdogTestEngine{
		pingCallback: pingCallback,
	}
	wd := newWatchdogTest(t, e, func(string) {})

	wd.Ping(netip.Addr{}, tailcfg.PingDisco, func(*ipnstate.PingResult) {
		callbackCalled <- struct{}{}
	})
	callback := <-pingCallback
	if !wd.poison("test") {
		t.Fatal("failed to poison healthy watchdog")
	}
	callback(&ipnstate.PingResult{})
	select {
	case <-callbackCalled:
		t.Fatal("callback ran after watchdog poison")
	default:
	}
}
