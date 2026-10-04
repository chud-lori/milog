//go:build unix

package tail

import (
	"os"
	"syscall"
)

// inode lets the tailer spot rotation: same path, different inode.
func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
