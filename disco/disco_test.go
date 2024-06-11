// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package disco

import (
	"fmt"
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
			want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c",
		},
		{
			name: "ping_with_nodekey_src",
			m: &Ping{
				TxID:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				NodeKey: key.NodePublicFromRaw32(mem.B([]byte{1: 1, 2: 2, 30: 30, 31: 31})),
			},
			want: "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f",
		},
		{
			name: "pong",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("2.3.4.5:1234"),
			},
			want: "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2",
		},
		{
			name: "pongv6",
			m: &Pong{
				TxID: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
				Src:  mustIPPort("[fed0::12]:6666"),
			},
			want: "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a",
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

			gotHex := fmt.Sprintf("% x", got)
			if gotHex != tt.want {
				t.Fatalf("wrong marshal\n got: %s\nwant: %s\n", gotHex, tt.want)
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

func mustIPPort(s string) netip.AddrPort {
	ipp, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ipp
}

func TestPaddedPings(t *testing.T) {
	priv0 := key.NewDisco()
	priv1 := key.NewDisco()
	sk := priv0.Shared(priv1.Public())
	ping := &Ping{
		TxID: [12]byte{1, 2},
	}
	plain := ping.AppendMarshal(nil)
	t.Logf("plaintext len: %d", len(plain))
	cipher := sk.Seal(plain)
	t.Logf("ciphertext len: %d", len(cipher))

	pkt := make([]byte, 0)
	pkt = append(pkt, Magic...)
	pkt = priv0.Public().AppendTo(pkt)
	pkt = append(pkt, cipher...)
	t.Logf("pkt len: %d", len(pkt))
	if len(pkt) != 1310 {
		t.Fatal("wrong pkt size")
	}

	const headerLen = len(Magic) + key.DiscoPublicRawLen
	sealedBox := pkt[headerLen:]
	payload, ok := sk.Open(sealedBox)
	if !ok {
		t.Fatalf("failed to open sealed box")
	}
	got, err := Parse(payload)
	if err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}
	gp := got.(*Ping)
	if !reflect.DeepEqual(gp, ping) {
		t.Fatalf("got %v, want %v", gp, ping)
	}
}

func TestPaddedPongs(t *testing.T) {
	priv0 := key.NewDisco()
	priv1 := key.NewDisco()
	sk := priv0.Shared(priv1.Public())
	pong := &Pong{
		TxID: [12]byte{1, 2},
		Src:  mustIPPort("44.55.66.77:8888"),
	}
	plain := pong.AppendMarshal(nil)
	t.Logf("plaintext len: %d", len(plain))
	cipher := sk.Seal(plain)
	t.Logf("ciphertext len: %d", len(cipher))

	pkt := make([]byte, 0)
	pkt = append(pkt, Magic...)
	pkt = priv0.Public().AppendTo(pkt)
	pkt = append(pkt, cipher...)
	t.Logf("pkt len: %d", len(pkt))
	if len(pkt) != 1310 {
		t.Fatal("wrong pkt size")
	}

	const headerLen = len(Magic) + key.DiscoPublicRawLen
	sealedBox := pkt[headerLen:]
	payload, ok := sk.Open(sealedBox)
	if !ok {
		t.Fatalf("failed to open sealed box")
	}
	got, err := Parse(payload)
	if err != nil {
		t.Fatalf("failed to parse payload: %v", err)
	}
	gp := got.(*Pong)
	if !reflect.DeepEqual(gp, pong) {
		t.Fatalf("got %v, want %v", gp, pong)
	}
}
