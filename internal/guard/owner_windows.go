package guard

import "os"

// ownerOf has no user id to report on Windows: the permission bits alone
// are checked.
func ownerOf(os.FileInfo) (int, bool) { return 0, false }
