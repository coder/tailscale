// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tshttpproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/alexbrainman/sspi/negotiate"
	"golang.org/x/sys/windows"
	"tailscale.com/hostinfo"
	"tailscale.com/syncs"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/cmpver"
)

func init() {
	sysProxyFromEnv = proxyFromWinHTTPOrCache
	sysAuthHeader = sysAuthHeaderWindows
}

// cachedProxy holds the most recent successful WPAD result and the
// InvalidateCache epoch it was discovered under. The timeout branch of
// proxyFromWinHTTPOrCache reads val as a fallback when an in-flight
// probe blows past the per-request deadline, but only when epoch
// matches the current one so we never strand the client on a proxy
// from a previous network.
var cachedProxy struct {
	sync.Mutex
	val   *url.URL
	epoch uint64
}

// proxyErrorf is a rate-limited logger specifically for errors asking
// WinHTTP for the proxy information. We don't want to log about
// errors often, otherwise the log message itself will generate a new
// HTTP request which ultimately will call back into us to log again,
// forever. So for errors, we only log a bit.
var proxyErrorf = logger.RateLimitedFn(log.Printf, 10*time.Minute, 2 /* burst*/, 10 /* maxCache */)

var (
	metricSuccess              = clientmetric.NewCounter("winhttp_proxy_success")
	metricErrDetectionFailed   = clientmetric.NewCounter("winhttp_proxy_err_detection_failed")
	metricErrInvalidParameters = clientmetric.NewCounter("winhttp_proxy_err_invalid_param")
	metricErrDownloadScript    = clientmetric.NewCounter("winhttp_proxy_err_download_script")
	metricErrTimeout           = clientmetric.NewCounter("winhttp_proxy_err_timeout")
	metricErrOther             = clientmetric.NewCounter("winhttp_proxy_err_other")
)

// WPAD negative-cache backoffs.
//
// Coder fork: previously these were 10s, which combined with
// InvalidateCache() being called on every netmon link change meant a
// host with no WPAD server (DHCP option 252 unset, no wpad.<domain> A
// record) would re-issue a 5-second blocking WinHttpGetProxyForUrl call
// for nearly every outbound HTTP request. Bumping the negative-cache
// duration lets normal traffic flow while still re-trying WPAD on
// every link change (via InvalidateCache, which zeros noProxyUntil).
//
// See tailscale/tailscale#17055 and tailscale/tailscale#10215.
const (
	wpadAutodetectFailedBackoff   = 5 * time.Minute
	wpadDownloadFailedBackoff     = 5 * time.Minute
	wpadTimeoutFailedBackoff      = 30 * time.Second
	wpadUnknownErrorFailedBackoff = 1 * time.Minute
	// wpadInvalidParameterFailedBackoff is intentionally long: this
	// error is only seen on Windows 8.1 and is not transient. See
	// tailscale/tailscale#879.
	wpadInvalidParameterFailedBackoff = 1 * time.Hour
)

// winHTTPLookup performs the underlying WPAD lookup. It is a package
// variable so tests can swap in a fake without exercising winhttp.dll.
var winHTTPLookup = proxyFromWinHTTP

func proxyFromWinHTTPOrCache(req *http.Request) (*url.URL, error) {
	if req.URL == nil {
		return nil, nil
	}
	urlStr := req.URL.String()

	// Snapshot the InvalidateCache epoch before launching the probe.
	// If a netmon link change increments the epoch while the probe is
	// in flight, we must not commit any state derived from this probe
	// (negative-cache backoff, cached-proxy fallback) onto the new
	// network — that probe's answer is for the old network only.
	startEpoch := CurrentEpoch()

	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
	defer cancel()

	type result struct {
		proxy *url.URL
		err   error
	}
	resc := make(chan result, 1)
	go func() {
		proxy, err := winHTTPLookup(ctx, urlStr)
		resc <- result{proxy, err}
	}()

	// setBackoff applies a negative-cache backoff only if the
	// InvalidateCache epoch hasn't advanced since the probe started.
	// Stale probes from a previous network must not gate fresh
	// lookups on the current one.
	setBackoff := func(d time.Duration) {
		if CurrentEpoch() != startEpoch {
			return
		}
		setNoProxyUntil(d)
	}

	select {
	case res := <-resc:
		err := res.err
		if err == nil {
			metricSuccess.Add(1)
			cachedProxy.Lock()
			defer cachedProxy.Unlock()
			if was, now := fmt.Sprint(cachedProxy.val), fmt.Sprint(res.proxy); was != now {
				log.Printf("tshttpproxy: winhttp: updating cached proxy setting from %v to %v", was, now)
			}
			cachedProxy.val = res.proxy
			cachedProxy.epoch = startEpoch
			return res.proxy, nil
		}

		// See https://docs.microsoft.com/en-us/windows/win32/winhttp/error-messages
		const (
			ERROR_WINHTTP_AUTODETECTION_FAILED      = 12180
			ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167
		)
		if err == syscall.Errno(ERROR_WINHTTP_AUTODETECTION_FAILED) {
			metricErrDetectionFailed.Add(1)
			setBackoff(wpadAutodetectFailedBackoff)
			return nil, nil
		}
		if err == windows.ERROR_INVALID_PARAMETER {
			metricErrInvalidParameters.Add(1)
			setBackoff(wpadInvalidParameterFailedBackoff)
			proxyErrorf("tshttpproxy: winhttp: GetProxyForURL(%q): ERROR_INVALID_PARAMETER [unexpected]", urlStr)
			return nil, nil
		}
		proxyErrorf("tshttpproxy: winhttp: GetProxyForURL(%q): %v/%#v", urlStr, err, err)
		if err == syscall.Errno(ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT) {
			metricErrDownloadScript.Add(1)
			setBackoff(wpadDownloadFailedBackoff)
			return nil, nil
		}
		metricErrOther.Add(1)
		// Coder fork: every error path here returns (nil, nil) so the
		// caller dials direct rather than failing the request. See the
		// package-level ProxyFromEnvironment doc and the const block
		// rationale above.
		setBackoff(wpadUnknownErrorFailedBackoff)
		return nil, nil
	case <-ctx.Done():
		metricErrTimeout.Add(1)
		// Coder fork: prefer the most recent successful WPAD result,
		// but only if it was discovered under the current epoch. A
		// cached proxy from a previous network would route this
		// request through a now-unreachable host. When the cache is
		// stale or empty, fall through to direct and apply a short
		// backoff so in-flight WinHTTP probes don't pile up.
		cachedProxy.Lock()
		fallback := cachedProxy.val
		fallbackEpoch := cachedProxy.epoch
		cachedProxy.Unlock()
		if fallback != nil && fallbackEpoch == startEpoch {
			proxyErrorf("tshttpproxy: winhttp: GetProxyForURL(%q): timeout; using cached proxy %v", urlStr, fallback)
			return fallback, nil
		}
		setBackoff(wpadTimeoutFailedBackoff)
		proxyErrorf("tshttpproxy: winhttp: GetProxyForURL(%q): timeout; falling back to direct", urlStr)
		return nil, nil
	}
}

func proxyFromWinHTTP(ctx context.Context, urlStr string) (proxy *url.URL, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	whi, err := httpOpen()
	if err != nil {
		proxyErrorf("winhttp: Open: %v", err)
		return nil, err
	}
	defer whi.Close()

	t0 := time.Now()
	v, err := whi.GetProxyForURL(urlStr)
	td := time.Since(t0).Round(time.Millisecond)
	if err := ctx.Err(); err != nil {
		log.Printf("tshttpproxy: winhttp: context canceled, ignoring GetProxyForURL(%q) after %v", urlStr, td)
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if v == "" {
		return nil, nil
	}
	// Discard all but first proxy value for now.
	if i := strings.Index(v, ";"); i != -1 {
		v = v[:i]
	}
	if !strings.HasPrefix(v, "https://") {
		v = "http://" + v
	}
	return url.Parse(v)
}

var userAgent = windows.StringToUTF16Ptr("Tailscale")

const (
	winHTTP_ACCESS_TYPE_DEFAULT_PROXY   = 0
	winHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4
	winHTTP_AUTOPROXY_ALLOW_AUTOCONFIG  = 0x00000100
	winHTTP_AUTOPROXY_AUTO_DETECT       = 1
	winHTTP_AUTO_DETECT_TYPE_DHCP       = 0x00000001
	winHTTP_AUTO_DETECT_TYPE_DNS_A      = 0x00000002
)

// Windows 8.1 is actually Windows 6.3 under the hood. Yay, marketing!
const win8dot1Ver = "6.3"

// accessType is the flag we must pass to WinHttpOpen for proxy resolution
// depending on whether or not we're running Windows < 8.1
var accessType syncs.AtomicValue[uint32]

func getAccessFlag() uint32 {
	if flag, ok := accessType.LoadOk(); ok {
		return flag
	}
	var flag uint32
	if cmpver.Compare(hostinfo.GetOSVersion(), win8dot1Ver) < 0 {
		flag = winHTTP_ACCESS_TYPE_DEFAULT_PROXY
	} else {
		flag = winHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
	}
	accessType.Store(flag)
	return flag
}

func httpOpen() (winHTTPInternet, error) {
	return winHTTPOpen(
		userAgent,
		getAccessFlag(),
		nil, /* WINHTTP_NO_PROXY_NAME */
		nil, /* WINHTTP_NO_PROXY_BYPASS */
		0,
	)
}

type winHTTPInternet windows.Handle

func (hi winHTTPInternet) Close() error {
	return winHTTPCloseHandle(hi)
}

// WINHTTP_AUTOPROXY_OPTIONS
// https://docs.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_autoproxy_options
type winHTTPAutoProxyOptions struct {
	DwFlags                uint32
	DwAutoDetectFlags      uint32
	AutoConfigUrl          *uint16
	_                      uintptr
	_                      uint32
	FAutoLogonIfChallenged int32 // BOOL
}

// WINHTTP_PROXY_INFO
// https://docs.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_proxy_info
type winHTTPProxyInfo struct {
	AccessType  uint32
	Proxy       *uint16
	ProxyBypass *uint16
}

type winHGlobal windows.Handle

func globalFreeUTF16Ptr(p *uint16) error {
	return globalFree((winHGlobal)(unsafe.Pointer(p)))
}

func (pi *winHTTPProxyInfo) free() {
	if pi.Proxy != nil {
		globalFreeUTF16Ptr(pi.Proxy)
		pi.Proxy = nil
	}
	if pi.ProxyBypass != nil {
		globalFreeUTF16Ptr(pi.ProxyBypass)
		pi.ProxyBypass = nil
	}
}

var proxyForURLOpts = &winHTTPAutoProxyOptions{
	DwFlags:           winHTTP_AUTOPROXY_ALLOW_AUTOCONFIG | winHTTP_AUTOPROXY_AUTO_DETECT,
	DwAutoDetectFlags: winHTTP_AUTO_DETECT_TYPE_DHCP, // | winHTTP_AUTO_DETECT_TYPE_DNS_A,
}

func (hi winHTTPInternet) GetProxyForURL(urlStr string) (string, error) {
	var out winHTTPProxyInfo
	err := winHTTPGetProxyForURL(
		hi,
		windows.StringToUTF16Ptr(urlStr),
		proxyForURLOpts,
		&out,
	)
	if err != nil {
		return "", err
	}
	defer out.free()
	return windows.UTF16PtrToString(out.Proxy), nil
}

func sysAuthHeaderWindows(u *url.URL) (string, error) {
	spn := "HTTP/" + u.Hostname()
	creds, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return "", fmt.Errorf("negotiate.AcquireCurrentUserCredentials: %w", err)
	}
	defer creds.Release()

	secCtx, token, err := negotiate.NewClientContext(creds, spn)
	if err != nil {
		return "", fmt.Errorf("negotiate.NewClientContext: %w", err)
	}
	defer secCtx.Release()

	return "Negotiate " + base64.StdEncoding.EncodeToString(token), nil
}
