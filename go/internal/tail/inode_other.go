//go:build !unix

package tail

import "os"

// inode falls back to mtime on platforms without syscall.Stat_t
// (Windows primarily). Rotation detection degrades from "exact" to
// "best-effort" — if the mtime happens to repeat, a rotation event
// may be missed for one poll interval. Acceptable trade.
func inode(fi os.FileInfo) uint64 {
	return uint64(fi.ModTime().UnixNano())
}
