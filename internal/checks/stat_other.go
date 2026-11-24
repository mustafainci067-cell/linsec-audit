//go:build !linux

package checks

import "io/fs"

func extractOwner(_ fs.FileInfo) (uint32, uint32) {
	return 0, 0
}
