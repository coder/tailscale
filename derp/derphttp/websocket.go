// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package derphttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"nhooyr.io/websocket"
	"tailscale.com/net/wsconn"
)

func init() {
	dialWebsocketFunc = dialWebsocket
}

func dialWebsocket(ctx context.Context, urlStr string, tlsConfig *tls.Config, httpHeader http.Header) (net.Conn, error) {
	c, _, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		Subprotocols: []string{"derp"},
		HTTPHeader:   httpHeader,
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	})
	// We can't log anything here, otherwise it'll appear in SSH output!
	if err != nil {
		// log.Printf("websocket Dial: %v, %+v", err, res)
		return nil, err
	}
	// log.Printf("websocket: connected to %v", urlStr)
	netConn := wsconn.NetConn(context.Background(), c, websocket.MessageBinary, urlStr)
	return netConn, nil
}
