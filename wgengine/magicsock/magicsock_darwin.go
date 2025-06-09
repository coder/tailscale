package magicsock

import (
	"net"

	"golang.org/x/sys/unix"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func trySetPathMTUDiscover(pconn nettype.PacketConn, logf logger.Logf, network string) {
	if c, ok := pconn.(*net.UDPConn); ok {
		s, err := c.SyscallConn()
		if err != nil {
			logf("magicsock: failed to set Path MTU Discover: get syscall conn: %v", err)
		}
		level := unix.IPPROTO_IP
		option := unix.IP_MTU_DISCOVER
		if network == "udp6" {
			level = unix.IPPROTO_IPV6
			option = unix.IPV6_MTU_DISCOVER
		}
		err = s.Control(func(fd uintptr) {
			err := unix.SetsockoptInt(int(fd), level, option, unix.IP_PMTUDISC_DO)
			if err != nil {
				logf("magicsock: failed to set Path MTU Discover: SetsockoptInt failed: %v", err)
			}
		})
		if err != nil {
			logf("magicsock: failed to set Path MTU Discover: control connection: %v", err)
		}
		logf("magicsock: successfully set Path MTU Discover on %s", pconn.LocalAddr().String())
		return
	}
	logf("magicsock: failed to set Path MTU Discover: not a UDPConn")
}
