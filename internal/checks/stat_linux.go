//go:build linux

package checks

import (
	"io/fs"
	"syscall"
)

func extractOwner(info fs.FileInfo) (uint32, uint32) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
		return st.Uid, st.Gid
	}
	return 0, 0
}
