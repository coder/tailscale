// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"fmt"
	"testing"

	"tailscale.com/net/tsaddr"
)

func TestShouldBindToDefaultInterface(t *testing.T) {
	t.Run("Normal", func(t *testing.T) {
		tests := []struct {
			address string
			want    bool
		}{
			{"127.0.0.1:0", false},
			{"127.0.0.1:1234", false},
			{"1.2.3.4:0", true},
			{"1.2.3.4:1234", true},
		}

		for _, test := range tests {
			t.Run(test.address, func(t *testing.T) {
				got := shouldBindToDefaultInterface(t.Logf, test.address)
				if got != test.want {
					t.Errorf("want %v, got %v", test.want, got)
				}
			})
		}
	})

	t.Run("CoderSoftIsolation", func(t *testing.T) {
		SetCoderSoftIsolation(true)
		t.Cleanup(func() {
			SetCoderSoftIsolation(false)
		})

		tests := []struct {
			address string
			want    bool
		}{
			// localhost should still not bind to any interface.
			{"127.0.0.1:0", false},
			{"127.0.0.1:0", false},
			{"127.0.0.1:1234", false},
			{"127.0.0.1:1234", false},

			// Unspecified addresses should not be bound to any interface.
			{":1234", false},
			{":1234", false},
			{"0.0.0.0:1234", false},
			{"0.0.0.0:1234", false},
			{"[::]:1234", false},
			{"[::]:1234", false},

			// Special cases should always bind to default:
			{"[::%eth0]:1234", true}, // zones are not supported
			{"a:1234", true},         // not an IP

			// Coder IPs should bind to default.
			{fmt.Sprintf("[%s]:8080", tsaddr.CoderServiceIPv6()), true},
			{fmt.Sprintf("[%s]:8080", tsaddr.CoderV6Range().Addr().Next()), true},

			// Non-Coder IPs should not bind to default.
			{fmt.Sprintf("[%s]:8080", tsaddr.TailscaleServiceIPv6()), false},
			{fmt.Sprintf("%s:8080", tsaddr.TailscaleServiceIP()), false},
			{"1.2.3.4:8080", false},
		}

		for _, test := range tests {
			t.Run(test.address, func(t *testing.T) {
				got := shouldBindToDefaultInterface(t.Logf, test.address)
				if got != test.want {
					t.Errorf("want %v, got %v", test.want, got)
				}
			})
		}
	})
}
