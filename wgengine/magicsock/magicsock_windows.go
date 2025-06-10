package magicsock

import (
	"net"

	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

// https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/shared/ws2ipdef.h
const (
	IP_MTU_DISCOVER = 71 // IPV6_MTU_DISCOVER has the same value, which is nice.
	IP_PMTUDISC_DO  = 1
)

func tryPreventFragmentation(pconn nettype.PacketConn, logf logger.Logf, network string) {
	if c, ok := pconn.(*net.UDPConn); ok {
		s, err := c.SyscallConn()
		if err != nil {
			logf("magicsock: dontfrag: failed to get syscall conn: %v", err)
		}
		level := windows.IPPROTO_IP
		if network == "udp6" {
			level = windows.IPPROTO_IPV6
		}
		err = s.Control(func(fd uintptr) {
			err := windows.SetsockoptInt(windows.Handle(fd), level, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
			if err != nil {
				logf("magicsock: dontfrag: SetsockoptInt failed: %v", err)
			}
		})
		if err != nil {
			logf("magicsock: dontfrag: control connection failed: %v", err)
		}
		logf("magicsock: dontfrag: success on %s", pconn.LocalAddr().String())
		return
	}
	logf("magicsock: dontfrag: failed because it was not a UDPConn")
}
