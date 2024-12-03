// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js

package derphttp

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"

	"github.com/coder/websocket"
)

func init() {
	dialWebsocketFunc = dialWebsocket
}

func dialWebsocket(ctx context.Context, urlStr string, _ *tls.Config, _ http.Header) (net.Conn, error) {
	c, res, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		Subprotocols: []string{"derp"},
	})
	if err != nil {
		log.Printf("websocket Dial: %v, %+v", err, res)
		return nil, err
	}
	log.Printf("websocket: connected to %v", urlStr)
	netConn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return netConn, nil
}
