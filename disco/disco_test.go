// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package disco

import (
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func TestMarshalAndParse(t *testing.T) {
	tests := []struct {
		name string
		want string
		m    Message
	}{
		{
			name: "ping",
			m: &Ping{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			},
			want: "01 01 01 02 03 04 05 06 07 08 09 0a 0b 0c",
		},
		{
			name: "ping_with_nodekey_src",
			m: &Ping{
				TxID:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				NodeKey: key.NodePublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
			},
			want: "01 01 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f",
		},
		{
			name: "pong",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("2.3.4.5:1234"),
			},
			want: "02 01 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2",
		},
		{
			name: "pongv6",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("[fed0::12]:6666"),
			},
			want: "02 01 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a",
		},
		{
			name: "call_me_maybe",
			m:    &CallMeMaybe{},
			want: "03 00",
		},
		{
			name: "call_me_maybe_endpoints",
			m: &CallMeMaybe{
				MyNumber: []netip.AddrPort{
					netip.MustParseAddrPort("1.2.3.4:567"),
					netip.MustParseAddrPort("[2001::3456]:789"),
				},
			},
			want: "03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			foo := []byte("foo")
			got := string(tt.m.AppendMarshal(foo))
			got, ok := strings.CutPrefix(got, "foo")
			if !ok {
				t.Fatalf("didn't start with foo: got %q", got)
			}
			// CODER: 1310 is max size of a Wireguard packet we will send.
			expectedLen := 1310 - len(Magic) - keyLen - NonceLen - box.Overhead
			switch tt.m.(type) {
			case *Ping:
				if len(got) != expectedLen {
					t.Fatalf("Ping not padded: got len %d, want len %d", len(got), expectedLen)
				}
			case *Pong:
				if len(got) != expectedLen {
					t.Fatalf("Pong not padded: got len %d, want len %d", len(got), expectedLen)
				}
				// CallMeMaybe is unpadded
			}

			gotHex := fmt.Sprintf("% x", got)
			if !strings.HasPrefix(gotHex, tt.want) {
				t.Fatalf("wrong marshal\n got: %s\nwant prefix: %s\n", gotHex, tt.want)
			}

			back, err := Parse([]byte(got))
			if err != nil {
				t.Fatalf("parse back: %v", err)
			}
			if !reflect.DeepEqual(back, tt.m) {
				t.Errorf("message in %+v doesn't match Parse back result %+v", tt.m, back)
			}
		})
	}
}

func TestParsePingPongV0(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		m       Message
	}{
		{
			name: "ping",
			m: &Ping{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			},
			payload: []byte{0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
		},
		{
			name: "ping_with_nodekey_src",
			m: &Ping{
				TxID:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				NodeKey: key.NodePublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
			},
			payload: []byte{
				0x01, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
				0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x1f},
		},
		{
			name: "pong",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("2.3.4.5:1234"),
			},
			payload: []byte{
				0x02, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02, 0x03, 0x04, 0x05,
				0x04, 0xd2},
		},
		{
			name: "pongv6",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("[fed0::12]:6666"),
			},
			payload: []byte{
				0x02, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
				0xfe, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
				0x1a, 0x0a},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			back, err := Parse(tt.payload)
			if err != nil {
				t.Fatalf("parse back: %v", err)
			}
			if !reflect.DeepEqual(back, tt.m) {
				t.Errorf("message in %+v doesn't match Parse result %+v", tt.m, back)
			}
		})
	}
}

func mustIPPort(s string) netip.AddrPort {
	ipp, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ipp
}
