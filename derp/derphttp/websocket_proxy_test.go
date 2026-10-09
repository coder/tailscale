// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package derphttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestDialWebsocketUsesProxy: the DERP host does not resolve; the only way to reach it is the CONNECT proxy in
// HTTPS_PROXY. Without Proxy on the transport, dialWebsocket fails on DNS; with it, it tunnels through the proxy.
// tshttpproxy reads the environment once per process, so the body runs in a child process with HTTPS_PROXY set.
func TestDialWebsocketUsesProxy(t *testing.T) {
	if os.Getenv("DERPHTTP_WS_PROXY_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDialWebsocketUsesProxy$", "-test.v")
		cmd.Env = append(os.Environ(), "DERPHTTP_WS_PROXY_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	derpSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"derp"}})
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		_ = c.Write(r.Context(), websocket.MessageBinary, []byte("hello-derp"))
		time.Sleep(200 * time.Millisecond)
	}))
	defer derpSrv.Close()

	var mu sync.Mutex
	var targets []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		targets = append(targets, r.Host)
		mu.Unlock()
		up, err := net.Dial("tcp", derpSrv.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, _ := w.(http.Hijacker)
		down, _, _ := hj.Hijack()
		_, _ = down.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(up, down); up.Close() }()
		_, _ = io.Copy(down, up)
		down.Close()
	}))
	defer proxy.Close()
	for k, v := range map[string]string{"HTTPS_PROXY": proxy.URL, "https_proxy": proxy.URL, "NO_PROXY": "", "no_proxy": ""} {
		os.Setenv(k, v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialWebsocket(ctx, "https://derp.invalid/derp", &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		t.Fatalf("dialWebsocket: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 10)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello-derp" {
		t.Fatalf("read %q, %v", buf, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(targets) != 1 || targets[0] != "derp.invalid:443" {
		t.Fatalf("proxy CONNECT targets = %v, want [derp.invalid:443]", targets)
	}
}
