// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tshttpproxy

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/util/must"
)

// withCleanState resets package globals shared across these Windows
// tests and registers cleanup to put them back when the test exits.
func withCleanState(t *testing.T) {
	t.Helper()

	mu.Lock()
	prevNoProxyUntil := noProxyUntil
	prevEpoch := epoch
	noProxyUntil = time.Time{}
	mu.Unlock()

	cachedProxy.Lock()
	prevCachedVal := cachedProxy.val
	prevCachedEpoch := cachedProxy.epoch
	cachedProxy.val = nil
	cachedProxy.epoch = 0
	cachedProxy.Unlock()

	prevLookup := winHTTPLookup
	t.Cleanup(func() {
		winHTTPLookup = prevLookup
		mu.Lock()
		noProxyUntil = prevNoProxyUntil
		epoch = prevEpoch
		mu.Unlock()
		cachedProxy.Lock()
		cachedProxy.val = prevCachedVal
		cachedProxy.epoch = prevCachedEpoch
		cachedProxy.Unlock()
	})
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	return must.Get(url.Parse(s))
}

func newReq(t *testing.T) *http.Request {
	t.Helper()
	return &http.Request{URL: mustParseURL(t, "https://example.com/")}
}

// TestProxyFromWinHTTPOrCache_AutodetectFailed verifies that the
// "WPAD not configured" error path returns no proxy and applies the
// long autodetect backoff. This is the core "host has no WPAD" case.
func TestProxyFromWinHTTPOrCache_AutodetectFailed(t *testing.T) {
	withCleanState(t)

	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		// 12180 = ERROR_WINHTTP_AUTODETECTION_FAILED
		return nil, syscall.Errno(12180)
	}

	got, err := proxyFromWinHTTPOrCache(newReq(t))
	if err != nil {
		t.Fatalf("got err %v; want nil", err)
	}
	if got != nil {
		t.Fatalf("got proxy %v; want nil", got)
	}

	mu.Lock()
	until := noProxyUntil
	mu.Unlock()
	if d := time.Until(until); d < 4*time.Minute || d > 6*time.Minute {
		t.Fatalf("noProxyUntil set to ~%v from now; want ~%v", d, wpadAutodetectFailedBackoff)
	}
}

// TestProxyFromWinHTTPOrCache_UnknownError verifies that an unmapped
// WinHTTP error doesn't propagate to the caller (would fail the
// outbound HTTP request) and applies the shorter unknown-error backoff.
func TestProxyFromWinHTTPOrCache_UnknownError(t *testing.T) {
	withCleanState(t)

	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		return nil, syscall.Errno(99999) // not one we map
	}

	got, err := proxyFromWinHTTPOrCache(newReq(t))
	if err != nil {
		t.Fatalf("got err %v; want nil so caller dials direct", err)
	}
	if got != nil {
		t.Fatalf("got proxy %v; want nil", got)
	}

	mu.Lock()
	until := noProxyUntil
	mu.Unlock()
	if d := time.Until(until); d < 30*time.Second || d > 90*time.Second {
		t.Fatalf("noProxyUntil set to ~%v from now; want ~%v", d, wpadUnknownErrorFailedBackoff)
	}
}

// TestProxyFromWinHTTPOrCache_TimeoutNoCached verifies that on probe
// timeout with no cached proxy, the function returns no proxy and
// applies the timeout backoff — i.e. dials direct rather than failing
// the request.
func TestProxyFromWinHTTPOrCache_TimeoutNoCached(t *testing.T) {
	withCleanState(t)

	// Block until the parent's 5s context fires. We trim the test by
	// shortening that wait via context.WithTimeout in the parent — we
	// can't override here, so we just block long enough that the
	// parent gives up first.
	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// We need the request's context to be cancelled before the
	// internal 5s timeout to keep this test fast. Use a request
	// context with a 50ms deadline so ctx.Done() fires quickly.
	reqCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := (&http.Request{URL: mustParseURL(t, "https://example.com/")}).WithContext(reqCtx)

	got, err := proxyFromWinHTTPOrCache(req)
	if err != nil {
		t.Fatalf("got err %v; want nil", err)
	}
	if got != nil {
		t.Fatalf("got proxy %v; want nil (no cached fallback under fresh epoch)", got)
	}

	mu.Lock()
	until := noProxyUntil
	mu.Unlock()
	if d := time.Until(until); d < 10*time.Second || d > 60*time.Second {
		t.Fatalf("noProxyUntil set to ~%v from now; want ~%v", d, wpadTimeoutFailedBackoff)
	}
}

// TestProxyFromWinHTTPOrCache_TimeoutFreshCached verifies that on
// probe timeout, a cached proxy from the *current* epoch is returned
// as a fallback. This protects users on networks that legitimately
// require a proxy when WinHTTP transiently exceeds the per-request
// deadline.
func TestProxyFromWinHTTPOrCache_TimeoutFreshCached(t *testing.T) {
	withCleanState(t)

	cached := mustParseURL(t, "http://corp-proxy.example:3128")
	cachedProxy.Lock()
	cachedProxy.val = cached
	cachedProxy.epoch = CurrentEpoch()
	cachedProxy.Unlock()

	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := (&http.Request{URL: mustParseURL(t, "https://example.com/")}).WithContext(reqCtx)

	got, err := proxyFromWinHTTPOrCache(req)
	if err != nil {
		t.Fatalf("got err %v; want nil", err)
	}
	if got == nil || got.String() != cached.String() {
		t.Fatalf("got %v; want cached fallback %v", got, cached)
	}
}

// TestProxyFromWinHTTPOrCache_TimeoutStaleCached verifies that a
// cached proxy from a *previous* epoch (a network we have since
// roamed off of) is NOT returned on timeout, so we never strand the
// client on an old corp proxy after a link change.
func TestProxyFromWinHTTPOrCache_TimeoutStaleCached(t *testing.T) {
	withCleanState(t)

	staleProxy := mustParseURL(t, "http://old-corp-proxy.example:3128")
	cachedProxy.Lock()
	cachedProxy.val = staleProxy
	cachedProxy.epoch = CurrentEpoch() // current... but we'll bump
	cachedProxy.Unlock()

	// Simulate a link change: the cached proxy's epoch is now stale.
	InvalidateCache()

	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := (&http.Request{URL: mustParseURL(t, "https://example.com/")}).WithContext(reqCtx)

	got, err := proxyFromWinHTTPOrCache(req)
	if err != nil {
		t.Fatalf("got err %v; want nil", err)
	}
	if got != nil {
		t.Fatalf("got %v; want nil (stale cached proxy must not be returned after epoch advance)", got)
	}
}

// TestProxyFromWinHTTPOrCache_EpochStompProtection is the regression
// test for the deep-review P1: an in-flight WPAD probe must not stomp
// noProxyUntil after InvalidateCache() has advanced the epoch. Pre-fix,
// a probe issued on the previous network could return ~5s later with
// ERROR_WINHTTP_AUTODETECTION_FAILED and lock out WPAD on the new
// network for 5 full minutes.
func TestProxyFromWinHTTPOrCache_EpochStompProtection(t *testing.T) {
	withCleanState(t)

	// Coordinate the probe: it blocks until we release it, then
	// returns AUTODETECTION_FAILED as if it ran on the old network.
	release := make(chan struct{})
	var lookupStarted sync.WaitGroup
	lookupStarted.Add(1)
	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		lookupStarted.Done()
		<-release
		return nil, syscall.Errno(12180) // ERROR_WINHTTP_AUTODETECTION_FAILED
	}

	// Spawn the probe on a goroutine. proxyFromWinHTTPOrCache will
	// wait on the probe (ctx timeout 5s).
	type result struct {
		u   *url.URL
		err error
	}
	resc := make(chan result, 1)
	go func() {
		u, err := proxyFromWinHTTPOrCache(newReq(t))
		resc <- result{u, err}
	}()

	// Wait for the probe to start (so startEpoch has been captured).
	lookupStarted.Wait()

	// Simulate a link change: bump the epoch.
	InvalidateCache()

	// Now release the probe. It will return an autodetect-failed
	// error from the OLD network. setBackoff must be a no-op because
	// the epoch has advanced.
	close(release)

	res := <-resc
	if res.err != nil {
		t.Fatalf("got err %v; want nil", res.err)
	}
	if res.u != nil {
		t.Fatalf("got proxy %v; want nil", res.u)
	}

	// Crucial assertion: noProxyUntil must NOT be in the future. If
	// the stale probe stomped it, every request on the new network
	// would skip WPAD for 5 minutes.
	mu.Lock()
	until := noProxyUntil
	mu.Unlock()
	if !until.IsZero() && time.Until(until) > 0 {
		t.Fatalf("stale probe stomped noProxyUntil = %v (in %v); should be zero or past",
			until, time.Until(until))
	}
}

// TestProxyFromWinHTTPOrCache_Success verifies the happy path: a
// successful WPAD lookup returns the proxy and stamps the cache with
// the current epoch.
func TestProxyFromWinHTTPOrCache_Success(t *testing.T) {
	withCleanState(t)

	want := mustParseURL(t, "http://corp-proxy.example:3128")
	winHTTPLookup = func(ctx context.Context, urlStr string) (*url.URL, error) {
		return want, nil
	}

	got, err := proxyFromWinHTTPOrCache(newReq(t))
	if err != nil {
		t.Fatalf("got err %v; want nil", err)
	}
	if got == nil || got.String() != want.String() {
		t.Fatalf("got %v; want %v", got, want)
	}

	cachedProxy.Lock()
	cv := cachedProxy.val
	ce := cachedProxy.epoch
	cachedProxy.Unlock()
	if cv == nil || cv.String() != want.String() {
		t.Fatalf("cachedProxy.val = %v; want %v", cv, want)
	}
	if ce != CurrentEpoch() {
		t.Fatalf("cachedProxy.epoch = %d; want current epoch %d", ce, CurrentEpoch())
	}
}


