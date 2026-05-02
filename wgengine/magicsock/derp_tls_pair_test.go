// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"crypto/tls"
	"testing"
)

// loadDERPTLSPair reads the (cfg, bypass) pair the way magicsock/derp.go
// reads it on every reconnect. Used by tests to assert that paired writers
// never expose an inconsistent (cfg, bypass) pairing to readers.
func (c *Conn) loadDERPTLSPair() (cfg *tls.Config, bypass bool) {
	if p := c.derpTLSConfig.Load(); p != nil {
		return p.cfg, p.bypassTLSDial
	}
	return nil, false
}

func TestSetDERPTLSConfigPair(t *testing.T) {
	t.Run("legacy SetDERPTLSConfig: bypass false, cfg set", func(t *testing.T) {
		c := &Conn{}
		want := &tls.Config{}
		c.SetDERPTLSConfig(want)
		got, bypass := c.loadDERPTLSPair()
		if got != want {
			t.Fatalf("cfg: got %p, want %p", got, want)
		}
		if bypass {
			t.Fatal("bypass should default to false for SetDERPTLSConfig")
		}
	})

	t.Run("SetDERPTLSConfigWithBypass updates pair atomically", func(t *testing.T) {
		c := &Conn{}
		want := &tls.Config{}
		c.SetDERPTLSConfigWithBypass(want, true)
		got, bypass := c.loadDERPTLSPair()
		if got != want {
			t.Fatalf("cfg: got %p, want %p", got, want)
		}
		if !bypass {
			t.Fatal("bypass should be true")
		}

		// Switch to a different cfg with bypass=false in one call.
		other := &tls.Config{}
		c.SetDERPTLSConfigWithBypass(other, false)
		got, bypass = c.loadDERPTLSPair()
		if got != other {
			t.Fatalf("cfg after second set: got %p, want %p", got, other)
		}
		if bypass {
			t.Fatal("bypass should be false after second set")
		}
	})

}
