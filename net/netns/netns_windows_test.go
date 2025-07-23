// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netns

import (
	"strconv"
	"testing"

	"golang.org/x/sys/windows"
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
		getBestInterface = func(addr windows.Sockaddr, idx *uint32) error {
			*idx = 1
			return nil
		}
		t.Cleanup(func() {
			SetCoderSoftIsolation(false)
			getBestInterface = windows.GetBestInterfaceEx
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

				got := shouldBindToDefaultInterface(t.Logf, test.address)
				if got != test.want {
					t.Errorf("want %v, got %v", test.want, got)
				}
			})
		}
	})
}
