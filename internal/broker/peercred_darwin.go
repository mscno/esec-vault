//go:build darwin

package broker

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// solLocal is the socket level for local (unix domain) socket options on
// Darwin; x/sys/unix does not export it.
const solLocal = 0

// peerCredentials returns the uid of the process at the other end of the unix
// socket connection. macOS does not expose the peer pid via socket options, so
// pid is always 0.
func peerCredentials(conn *net.UnixConn) (uid, pid uint32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get raw conn: %w", err)
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), solLocal, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return cred.Uid, 0, nil
}
