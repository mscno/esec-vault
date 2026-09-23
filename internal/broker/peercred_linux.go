//go:build linux

package broker

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentials returns the uid and pid of the process at the other end of
// the unix socket connection.
func peerCredentials(conn *net.UnixConn) (uid, pid uint32, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get raw conn: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return cred.Uid, cred.Pid, nil
}
