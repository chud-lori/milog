//go:build !unix

package tail

import "os"

// inode falls back to mtime where syscall.Stat_t is unavailable; a rotation
// that keeps the mtime can go unnoticed for one poll.
func inode(fi os.FileInfo) uint64 {
	return uint64(fi.ModTime().UnixNano())
}
