// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import "testing"

func TestNetstackLinkMTU(t *testing.T) {
	tests := []struct {
		name string
		mtu  string
		want uint32
	}{
		{name: "default", want: minimumIPv6LinkMTU},
		{name: "below IPv6 minimum", mtu: "1182", want: minimumIPv6LinkMTU},
		{name: "IPv6 minimum", mtu: "1280", want: minimumIPv6LinkMTU},
		{name: "above IPv6 minimum", mtu: "1420", want: 1420},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_DEBUG_MTU", tt.mtu)
			if got := netstackLinkMTU(); got != tt.want {
				t.Fatalf("netstackLinkMTU() = %d, want %d", got, tt.want)
			}
		})
	}
}
