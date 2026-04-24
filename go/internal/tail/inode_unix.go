//go:build unix

package tail

import (
	"os"
	"syscall"
)

// inode returns the filesystem inode from a FileInfo on unix systems.
// Used to detect logrotate-style rotations: the path stays the same
// but the inode differs.
func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
