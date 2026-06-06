package filesystem_apfs

// timestamps.go centralises in-place timestamp updates on inode values
// (J_INODE_VAL). The four 8-byte timestamps live at offsets 16/24/32/40
// of the inode base (per apfs_raw.h::apfs_inode_val):
//
//	+16 create_time
//	+24 mod_time
//	+32 change_time
//	+40 access_time
//
// Convention: callers set `mod=true` when the operation modifies the
// file's CONTENT (mtime + ctime + atime updated) and `mod=false` for
// pure-metadata changes (only ctime updated). create_time is never
// touched — it's set once at CreateFile/CreateDirectory time.

import (
	"encoding/binary"
	"time"
)

const (
	inodeOffCreateTime = 16
	inodeOffModTime    = 24
	inodeOffChangeTime = 32
	inodeOffAccessTime = 40
)

// touchInodeTimes patches the timestamps in the supplied inode val
// (val[0:92] is the apfs_inode_val base; offsets 16/24/32/40 are the
// four uint64 timestamps in nanoseconds since the Unix epoch). Caller
// is responsible for re-sealing whatever block the val lives in.
//
// mod=true → mtime + ctime + atime all updated (POSIX `pwrite` /
// `truncate` semantics, atime-on-write per default).
// mod=false → only ctime updated (POSIX metadata-change ops like
// chmod, chown, rename, link, setxattr).
func touchInodeTimes(val []byte, mod bool) {
	if len(val) < inodeOffAccessTime+8 {
		return
	}
	now := uint64(time.Now().UnixNano())
	if mod {
		binary.LittleEndian.PutUint64(val[inodeOffModTime:inodeOffModTime+8], now)
		binary.LittleEndian.PutUint64(val[inodeOffAccessTime:inodeOffAccessTime+8], now)
	}
	binary.LittleEndian.PutUint64(val[inodeOffChangeTime:inodeOffChangeTime+8], now)
}
