package magicsock

import (
	"net"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func tryPreventFragmentation(pconn nettype.PacketConn, logf logger.Logf, network string) {
	if c, ok := pconn.(*net.UDPConn); ok {
		s, err := c.SyscallConn()
		if err != nil {
			logf("magicsock: dontfrag: failed to get syscall conn: %v", err)
		}
		level := unix.IPPROTO_IP
		option := unix.IP_DONTFRAG
		if network == "udp6" {
			level = unix.IPPROTO_IPV6
			option = unix.IPV6_DONTFRAG
		}
		err = s.Control(func(fd uintptr) {
			err := unix.SetsockoptInt(int(fd), level, option, 1)
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
