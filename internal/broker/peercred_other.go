//go:build !linux && !darwin

package broker

import (
	"fmt"
	"net"
)

// peerCredentials is unsupported on this platform; the broker refuses to
// serve rather than serve without peer authentication.
func peerCredentials(conn *net.UnixConn) (uid, pid uint32, err error) {
	return 0, 0, fmt.Errorf("peer credentials are not supported on this platform")
}
