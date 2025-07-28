// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"strconv"
	"testing"

	"tailscale.com/net/interfaces"
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
				got := shouldBindToDefaultInterface(t.Logf, nil, test.address)
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
			address          string
			isCoderInterface bool
			want             bool
		}{
			// isCoderInterface shouldn't even matter for localhost since it has
			// a special exemption.
			{"127.0.0.1:0", false, false},
			{"127.0.0.1:0", true, false},
			{"127.0.0.1:1234", false, false},
			{"127.0.0.1:1234", true, false},

			{"1.2.3.4:0", false, false},
			{"1.2.3.4:0", true, true},
			{"1.2.3.4:1234", false, false},
			{"1.2.3.4:1234", true, true},

			// Unspecified addresses should not be bound to any interface.
			{":0", false, false},
			{":0", true, false},
			{":1234", false, false},
			{":1234", true, false},
			{"0.0.0.0:1234", false, false},
			{"0.0.0.0:1234", true, false},
			{"[::]:1234", false, false},
			{"[::]:1234", true, false},

			// Special cases should always bind to default:
			{"[::%eth0]:1234", false, true}, // zones are not supported
			{"1.2.3.4:", false, true},       // port is empty
			{"1.2.3.4:a", false, true},      // port is not a number
			{"1.2.3.4:-1", false, true},     // port is negative
			{"1.2.3.4:65536", false, true},  // port is too large
		}

		for _, test := range tests {
			name := test.address + " (isCoderInterface=" + strconv.FormatBool(test.isCoderInterface) + ")"
			t.Run(name, func(t *testing.T) {
				isInterfaceCoderInterface = func(_ int) bool {
					return test.isCoderInterface
				}
				defer func() {
					isInterfaceCoderInterface = isInterfaceCoderInterfaceDefault
				}()

				got := shouldBindToDefaultInterface(t.Logf, nil, test.address)
				if got != test.want {
					t.Errorf("want %v, got %v", test.want, got)
				}
			})
		}
	})
}

func TestGetInterfaceIndex(t *testing.T) {
	oldVal := bindToInterfaceByRoute.Load()
	t.Cleanup(func() { bindToInterfaceByRoute.Store(oldVal) })
	bindToInterfaceByRoute.Store(true)

	tests := []struct {
		name string
		addr string
		err  string
	}{
		{
			name: "IP_and_port",
			addr: "8.8.8.8:53",
		},
		{
			name: "bare_ip",
			addr: "8.8.8.8",
		},
		{
			name: "invalid",
			addr: "!!!!!",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			idx, err := getInterfaceIndex(t.Logf, nil, tc.addr)
			if err != nil {
				if tc.err == "" {
					t.Fatalf("got unexpected error: %v", err)
				}
				if errstr := err.Error(); errstr != tc.err {
					t.Errorf("expected error %q, got %q", errstr, tc.err)
				}
			} else {
				t.Logf("getInterfaceIndex(%q) = %d", tc.addr, idx)
				if tc.err != "" {
					t.Fatalf("wanted error %q", tc.err)
				}
				if idx < 0 {
					t.Fatalf("got invalid index %d", idx)
				}
			}
		})
	}

	t.Run("NoTailscale", func(t *testing.T) {
		_, tsif, err := interfaces.Coder()
		if err != nil {
			t.Fatal(err)
		}
		if tsif == nil {
			t.Skip("no tailscale interface on this machine")
		}

		defaultIdx, err := interfaces.DefaultRouteInterfaceIndex()
		if err != nil {
			t.Fatal(err)
		}

		idx, err := getInterfaceIndex(t.Logf, nil, "100.100.100.100:53")
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("tailscaleIdx=%d defaultIdx=%d idx=%d", tsif.Index, defaultIdx, idx)

		if idx == tsif.Index {
			t.Fatalf("got idx=%d; wanted not Tailscale interface", idx)
		} else if idx != defaultIdx {
			t.Fatalf("got idx=%d, want %d", idx, defaultIdx)
		}
	})
}
