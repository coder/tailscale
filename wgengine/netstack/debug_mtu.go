// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netstack

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"tailscale.com/net/tstun"
)

func debugTCPMSS() uint16 {
	mtu := int(tstun.DefaultMTU())
	if mtu >= int(netstackLinkMTU()) {
		return 0
	}
	return tcpMSSForMTU(mtu)
}

func tcpMSSForMTU(mtu int) uint16 {
	const ipv6AndTCPHeaderLen = 40 + header.TCPMinimumSize
	mss := mtu - ipv6AndTCPHeaderLen
	if mss < header.TCPMinimumMSS || mss > int(^uint16(0)) {
		return 0
	}
	return uint16(mss)
}

// clampDebugTCPMSS rewrites the MSS advertised by outbound TCP SYN and SYN-ACK
// packets when TS_DEBUG_MTU is below the IPv6 link minimum. This keeps the
// logical link standards-compliant while preventing TCP from producing inner
// packets larger than the explicitly configured nested-path budget.
func clampDebugTCPMSS(pkt *stack.PacketBuffer) {
	if pkt.TransportProtocolNumber != tcp.ProtocolNumber {
		return
	}
	mss := debugTCPMSS()
	if mss == 0 {
		return
	}
	clampTCPMSSOption(pkt.TransportHeader().Slice(), mss)
}

func clampTCPMSSOption(tcpHeader []byte, maxMSS uint16) bool {
	if len(tcpHeader) < header.TCPMinimumSize || tcpHeader[13]&byte(header.TCPFlagSyn) == 0 {
		return false
	}

	headerLen := int(tcpHeader[12]>>4) * 4
	if headerLen < header.TCPMinimumSize || headerLen > len(tcpHeader) {
		return false
	}

	for i := header.TCPMinimumSize; i < headerLen; {
		switch tcpHeader[i] {
		case header.TCPOptionEOL:
			return false
		case header.TCPOptionNOP:
			i++
			continue
		}

		if i+1 >= headerLen {
			return false
		}
		optionLen := int(tcpHeader[i+1])
		if optionLen < 2 || i+optionLen > headerLen {
			return false
		}
		if tcpHeader[i] == header.TCPOptionMSS && optionLen == header.TCPOptionMSSLength {
			oldMSS := binary.BigEndian.Uint16(tcpHeader[i+2 : i+4])
			if oldMSS <= maxMSS {
				return false
			}

			oldChecksum := binary.BigEndian.Uint16(tcpHeader[16:18])
			binary.BigEndian.PutUint16(tcpHeader[i+2:i+4], maxMSS)
			binary.BigEndian.PutUint16(tcpHeader[16:18], updateChecksumWord(oldChecksum, oldMSS, maxMSS))
			return true
		}
		i += optionLen
	}
	return false
}

// updateChecksumWord applies RFC 1624's incremental one's-complement checksum
// update for a single aligned 16-bit field.
func updateChecksumWord(checksum, old, new uint16) uint16 {
	sum := uint32(^checksum) + uint32(^old) + uint32(new)
	sum = (sum & 0xffff) + (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16)
	return ^uint16(sum)
}
