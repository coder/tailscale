// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestTCPMSSForMTU(t *testing.T) {
	if got, want := tcpMSSForMTU(1182), uint16(1122); got != want {
		t.Fatalf("tcpMSSForMTU(1182) = %d, want %d", got, want)
	}
	if got := tcpMSSForMTU(0); got != 0 {
		t.Fatalf("tcpMSSForMTU(0) = %d, want disabled", got)
	}
}

func TestDebugTCPMSS(t *testing.T) {
	tests := []struct {
		name string
		mtu  string
		want uint16
	}{
		{name: "default"},
		{name: "nested path", mtu: "1182", want: 1122},
		{name: "IPv6 minimum", mtu: "1280"},
		{name: "larger MTU", mtu: "1420"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_DEBUG_MTU", tt.mtu)
			if got := debugTCPMSS(); got != tt.want {
				t.Fatalf("debugTCPMSS() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestClampTCPMSSOption(t *testing.T) {
	const pseudoHeaderChecksum = uint16(0x2345)
	tcpHeader := make([]byte, header.TCPMinimumSize+header.TCPOptionMSSLength)
	binary.BigEndian.PutUint16(tcpHeader[0:2], 12345)
	binary.BigEndian.PutUint16(tcpHeader[2:4], 22)
	tcpHeader[12] = byte(len(tcpHeader)/4) << 4
	tcpHeader[13] = byte(header.TCPFlagSyn)
	tcpHeader[20] = header.TCPOptionMSS
	tcpHeader[21] = header.TCPOptionMSSLength
	binary.BigEndian.PutUint16(tcpHeader[22:24], 1220)
	binary.BigEndian.PutUint16(tcpHeader[16:18], ^checksum.Checksum(tcpHeader, pseudoHeaderChecksum))

	if changed := clampTCPMSSOption(tcpHeader, 1122); !changed {
		t.Fatal("clampTCPMSSOption did not change an oversized MSS")
	}
	if got, want := binary.BigEndian.Uint16(tcpHeader[22:24]), uint16(1122); got != want {
		t.Fatalf("MSS = %d, want %d", got, want)
	}
	if got := checksum.Checksum(tcpHeader, pseudoHeaderChecksum); got != 0xffff {
		t.Fatalf("updated TCP checksum sum = %#04x, want 0xffff", got)
	}
	if changed := clampTCPMSSOption(tcpHeader, 1122); changed {
		t.Fatal("clampTCPMSSOption changed an already safe MSS")
	}
}

func TestClampTCPMSSOptionIgnoresNonSYN(t *testing.T) {
	tcpHeader := make([]byte, header.TCPMinimumSize+header.TCPOptionMSSLength)
	tcpHeader[12] = byte(len(tcpHeader)/4) << 4
	tcpHeader[13] = byte(header.TCPFlagAck)
	tcpHeader[20] = header.TCPOptionMSS
	tcpHeader[21] = header.TCPOptionMSSLength
	binary.BigEndian.PutUint16(tcpHeader[22:24], 1220)

	if changed := clampTCPMSSOption(tcpHeader, 1122); changed {
		t.Fatal("clampTCPMSSOption changed a non-SYN packet")
	}
}
