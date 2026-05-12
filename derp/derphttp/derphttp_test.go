// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/derp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestSendRecv(t *testing.T) {
	serverPrivateKey := key.NewNode()

	const numClients = 3
	var clientPrivateKeys []key.NodePrivate
	var clientKeys []key.NodePublic
	for i := 0; i < numClients; i++ {
		priv := key.NewNode()
		clientPrivateKeys = append(clientPrivateKeys, priv)
		clientKeys = append(clientKeys, priv.Public())
	}

	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + ln.Addr().String()
	t.Logf("server URL: %s", serverURL)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			panic(err)
		}
	}()

	var clients []*Client
	var recvChs []chan []byte
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(done)
		for _, c := range clients {
			c.Close()
		}
		wg.Wait()
	}()
	for i := 0; i < numClients; i++ {
		key := clientPrivateKeys[i]
		c, err := NewClient(key, serverURL, t.Logf)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if err := c.Connect(context.Background()); err != nil {
			t.Fatalf("client %d Connect: %v", i, err)
		}
		waitConnect(t, c)
		clients = append(clients, c)
		recvChs = append(recvChs, make(chan []byte))

		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				m, err := c.Recv()
				if err != nil {
					select {
					case <-done:
						return
					default:
					}
					t.Logf("client%d: %v", i, err)
					break
				}
				switch m := m.(type) {
				default:
					t.Errorf("unexpected message type %T", m)
					continue
				case derp.PeerGoneMessage:
					// Ignore.
				case derp.ReceivedPacket:
					recvChs[i] <- bytes.Clone(m.Data)
				}
			}
		}(i)
	}

	recv := func(i int, want string) {
		t.Helper()
		select {
		case b := <-recvChs[i]:
			if got := string(b); got != want {
				t.Errorf("client1.Recv=%q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("client%d.Recv, got nothing, want %q", i, want)
		}
	}
	recvNothing := func(i int) {
		t.Helper()
		select {
		case b := <-recvChs[0]:
			t.Errorf("client%d.Recv=%q, want nothing", i, string(b))
		default:
		}
	}

	msg1 := []byte("hello 0->1\n")
	if err := clients[0].Send(clientKeys[1], msg1); err != nil {
		t.Fatal(err)
	}
	recv(1, string(msg1))
	recvNothing(0)
	recvNothing(2)

	msg2 := []byte("hello 1->2\n")
	if err := clients[1].Send(clientKeys[2], msg2); err != nil {
		t.Fatal(err)
	}
	recv(2, string(msg2))
	recvNothing(0)
	recvNothing(1)
}

func waitConnect(t testing.TB, c *Client) {
	t.Helper()
	if m, err := c.Recv(); err != nil {
		t.Fatalf("client first Recv: %v", err)
	} else if v, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("client first Recv was unexpected type %T", v)
	}
}

func TestPing(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + ln.Addr().String()
	t.Logf("server URL: %s", serverURL)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			panic(err)
		}
	}()

	c, err := NewClient(key.NewNode(), serverURL, t.Logf)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("client Connect: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		for {
			m, err := c.Recv()
			if err != nil {
				errc <- err
				return
			}
			t.Logf("Recv: %T", m)
		}
	}()
	err = c.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestHTTP2OnlyServer(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := r.Header.Get("Upgrade")
		if up != "websocket" {
			Handler(s).ServeHTTP(w, r)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			t.Errorf("websocket.Accept: %v", err)
			return
		}
		defer c.Close(websocket.StatusInternalError, "closing")
		wc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
		brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
		s.Accept(context.Background(), wc, brw, r.RemoteAddr)
	}))
	defer httpsrv.Close()
	httpsrv.TLS = &tls.Config{
		NextProtos: []string{"h2"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Add this to ensure fast start works!
			cert := httpsrv.TLS.Certificates[0]
			cert.Certificate = append(cert.Certificate, s.MetaCert())
			return &cert, nil
		},
	}
	httpsrv.StartTLS()

	serverURL := httpsrv.URL
	t.Logf("server URL: %s", serverURL)

	c, err := NewClient(key.NewNode(), serverURL, t.Logf)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.TLSConfig = &tls.Config{
		ServerName: "example.com",
		RootCAs:    httpsrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}
	defer c.Close()

	err = c.Connect(context.Background())
	if err != nil {
		t.Fatalf("client errored initial connect: %v", err)
	}

	c.Close()
}

func TestForceWebsockets(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := r.Header.Get("Upgrade")
		if up == "" {
			Handler(s).ServeHTTP(w, r)
			return
		}
		if up != "websocket" {
			// Should only attempt to upgrade to websocket.
			t.Errorf("unexpected Upgrade header: %q", up)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
		if err != nil {
			t.Errorf("websocket.Accept: %v", err)
			return
		}
		defer c.Close(websocket.StatusInternalError, "closing")
		wc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
		brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
		s.Accept(context.Background(), wc, brw, r.RemoteAddr)
	}))
	defer httpsrv.Close()
	httpsrv.TLS = &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Add this to ensure fast start works!
			cert := httpsrv.TLS.Certificates[0]
			cert.Certificate = append(cert.Certificate, s.MetaCert())
			return &cert, nil
		},
	}
	httpsrv.StartTLS()

	serverURL := httpsrv.URL
	t.Logf("server URL: %s", serverURL)

	c, err := NewClient(key.NewNode(), serverURL, t.Logf)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.ForceWebsockets = true
	c.TLSConfig = &tls.Config{
		ServerName: "example.com",
		RootCAs:    httpsrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}
	defer c.Close()

	err = c.Connect(context.Background())
	if err != nil {
		t.Fatalf("client errored initial connect: %v", err)
	}

	c.Close()
}

func TestClientHeaders(t *testing.T) {
	t.Run("nil when neither set", func(t *testing.T) {
		c := &Client{}
		if got := c.headers(); got != nil {
			t.Fatalf("expected nil headers, got %v", got)
		}
	})
	t.Run("returns Header when GetHeaders is nil", func(t *testing.T) {
		want := http.Header{"X-Test": []string{"static"}}
		c := &Client{Header: want}
		if got := c.headers().Get("X-Test"); got != "static" {
			t.Fatalf("expected static header, got %q", got)
		}
	})
	t.Run("GetHeaders takes precedence and is invoked on every call", func(t *testing.T) {
		var calls int
		c := &Client{
			Header: http.Header{"X-Test": []string{"static"}},
			GetHeaders: func() http.Header {
				calls++
				return http.Header{"X-Test": []string{"dynamic"}}
			},
		}
		if got := c.headers().Get("X-Test"); got != "dynamic" {
			t.Fatalf("expected dynamic header, got %q", got)
		}
		_ = c.headers()
		if calls != 2 {
			t.Fatalf("expected GetHeaders to be invoked on every call, got %d calls", calls)
		}
	})
}

func TestTLSConfigBypassesTLSDial(t *testing.T) {
	node := &tailcfg.DERPNode{HostName: "derp.example.com"}

	t.Run("default path wraps via tlsdial.Config", func(t *testing.T) {
		// tlsdial.Config installs its own VerifyConnection. Confirming it
		// runs is the easiest way to assert we did NOT bypass it. We must
		// not pass a base config that would cause tlsdial.Config to panic.
		c := &Client{TLSConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
		got := c.tlsConfig(node)
		if got.VerifyConnection == nil {
			t.Fatal("expected default path to install tlsdial's VerifyConnection")
		}
		if !got.InsecureSkipVerify {
			t.Fatal("expected default path to set InsecureSkipVerify (tlsdial does its own verify)")
		}
		if got.ServerName != node.HostName {
			t.Fatalf("ServerName: got %q, want %q", got.ServerName, node.HostName)
		}
	})

	t.Run("bypass path uses caller config as-is", func(t *testing.T) {
		// A typical "I'm bringing my own verifier" config that would make
		// tlsdial.Config panic.
		base := &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return nil
			},
		}
		c := &Client{TLSConfig: base, TLSConfigBypassesTLSDial: true}
		got := c.tlsConfig(node)
		if got == base {
			t.Fatal("expected tlsConfig to clone the base config")
		}
		if got.VerifyConnection != nil {
			t.Fatal("bypass path must not install tlsdial's VerifyConnection")
		}
		if !got.InsecureSkipVerify {
			t.Fatal("bypass path must preserve caller's InsecureSkipVerify")
		}
		if got.VerifyPeerCertificate == nil {
			t.Fatal("bypass path must preserve caller's VerifyPeerCertificate")
		}
		if got.ServerName != node.HostName {
			t.Fatalf("ServerName fallback: got %q, want %q", got.ServerName, node.HostName)
		}
		if want := []string{"http/1.1"}; len(got.NextProtos) != 1 || got.NextProtos[0] != want[0] {
			t.Fatalf("NextProtos: got %v, want %v", got.NextProtos, want)
		}
	})

	t.Run("bypass path preserves caller-set ServerName", func(t *testing.T) {
		base := &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return nil
			},
			ServerName: "explicit.example.com",
		}
		c := &Client{TLSConfig: base, TLSConfigBypassesTLSDial: true}
		got := c.tlsConfig(node)
		if got.ServerName != "explicit.example.com" {
			t.Fatalf("ServerName: got %q, want explicit.example.com", got.ServerName)
		}
	})

	t.Run("bypass flag without TLSConfig falls back to default path", func(t *testing.T) {
		c := &Client{TLSConfigBypassesTLSDial: true}
		got := c.tlsConfig(node)
		if got.VerifyConnection == nil {
			t.Fatal("expected fallback to tlsdial path when TLSConfig is nil")
		}
	})

	t.Run("bypass path honors node.InsecureForTests", func(t *testing.T) {
		base := &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				return nil
			},
		}
		c := &Client{TLSConfig: base, TLSConfigBypassesTLSDial: true}
		insecureNode := &tailcfg.DERPNode{HostName: "derp.example.com", InsecureForTests: true}
		got := c.tlsConfig(insecureNode)
		if !got.InsecureSkipVerify {
			t.Fatal("expected InsecureForTests to keep InsecureSkipVerify=true")
		}
		if got.VerifyPeerCertificate != nil {
			t.Fatal("expected InsecureForTests to clear VerifyPeerCertificate")
		}
		if got.VerifyConnection != nil {
			t.Fatal("expected InsecureForTests to clear VerifyConnection")
		}
	})
}
