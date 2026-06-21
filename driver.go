package filesystem_apfs

// driver.go — Go APFS filesystem driver. Wraps the real APFS
// reader/writer (`*Container` + `*Volume`) to satisfy the
// `filesystem.Filesystem` interface.
//
// Path resolution: APFS records keys by inode oid + name; the
// `filesystem.Filesystem` interface is path-based. The driver
// walks the FS-tree from the volume root (oid 2) splitting the
// supplied path on '/' and resolving one drec at a time. The walk
// is `O(depth × log n)` — cheap for typical disk-image trees with
// a few thousand entries.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-filesystems/interface"
)

// Compile-time assertions: driver satisfies the common Filesystem
// interface, the read-only LabelReader capability (full Labeller would
// require a transactional SetLabel via the volume superblock, which is
// out of scope here — see Label() docstring below), and the optional
// write capabilities whose machinery the Volume/Container layer already
// implements (Symlink/Hardlink/Truncate/Grow/Resize).
var (
	_ filesystem.Filesystem  = (*driver)(nil)
	_ filesystem.LabelReader = (*driver)(nil)
	_ filesystem.Symlinker   = (*driver)(nil)
	_ filesystem.HardLinker  = (*driver)(nil)
	_ filesystem.Truncater   = (*driver)(nil)
	_ filesystem.Grower      = (*driver)(nil)
	_ filesystem.Resizer     = (*driver)(nil)
)

// Label returns the APFS volume name (apfs_volname_t, NUL-trimmed
// UTF-8). Read-only: APFS volume rename has to go through a regular
// COW commit (xid bump, omap update, superblock checksum) which is
// significantly more involved than the simple block-level relabel
// other filesystems do — the driver therefore implements
// filesystem.LabelReader but not the full filesystem.Labeller.
func (d *driver) Label() string {
	if d.v == nil {
		return ""
	}
	return d.v.Name()
}

// driver wraps Container+Volume to satisfy filesystem.Filesystem.
type driver struct {
	c *Container
	v *Volume
	// mount-backed (darwin) fields — used when Open() falls through
	// to hdiutil-attach. When mountpoint != "" all method calls
	// proxy to the OS at that mountpoint instead of touching the
	// container directly.
	mountpoint string
	dev        string

	// pathCache memoises path → (oid, inode) resolutions to avoid
	// re-walking the FS-tree on every Stat/ReadFile/etc. The cache
	// is invalidated on every mutating call (CreateFile, MkDir,
	// DeleteFile, DeleteDir, Rename, WriteFile-of-new-file). Bound
	// is pathCacheCap entries; full cache simply clears on next
	// store (no LRU complexity — disk-image workloads typically
	// touch a few thousand paths, well under the cap).
	//
	// pathCacheMu guards every read and write of pathCache so that
	// concurrent driver-level callers (e.g. parallel ReadFile +
	// WriteFile on disjoint paths) don't race the underlying Go map.
	// The volume layer already serialises mutating operations via
	// Container.mu, so contention here is bounded to the small,
	// purely in-memory cache map.
	pathCacheMu  sync.RWMutex
	pathCache    map[string]cachedInode
	pathCacheCap int

	// opMu serialises driver-level compound operations.
	// The single-call Volume APIs (CreateFile, ReadFile, …) already
	// take Container.mu, but driver methods do multi-step work in
	// between — first a `lookupFSTreeFirst` outside the lock to
	// resolve the path, then a Volume mutator that takes the lock,
	// then a possible second lookup against `v.rootNode` that the
	// mutator just rewrote. Without a driver-level mutex two
	// concurrent driver calls can read `v.rootNode` while a third
	// is in the middle of `reloadRoot` swapping it out. We hold
	// opMu for the full duration of each driver method (RLock for
	// read-only, Lock for mutators) so the cross-call sequence is
	// atomic from the driver's perspective.
	opMu sync.RWMutex
}

// cachedInode is a path-cache entry. Stored under the driver lock
// alongside every other mutating operation, so no separate sync
// is needed.
type cachedInode struct {
	oid   uint64
	inode Inode
}

// pathCacheDefaultCap is the soft cap on cached path entries before
// the cache is flushed.
const pathCacheDefaultCap = 4096

// invalidatePathCache drops every cached entry. Called by every
// mutating method before it returns (regardless of success), since
// the affected oid layout may have changed.
func (d *driver) invalidatePathCache() {
	d.pathCacheMu.Lock()
	d.pathCache = nil
	d.pathCacheMu.Unlock()
}

// resolvePath walks the FS-tree from the volume root and returns the
// inode oid for `path`. Returns os.ErrNotExist when any component
// along the way is missing. Memoised via pathCache; the cache is
// dropped wholesale by `invalidatePathCache` on every mutation.
func (d *driver) resolvePath(path string) (uint64, Inode, error) {
	if cached, ok := d.pathCacheLookup(path); ok {
		return cached.oid, cached.inode, nil
	}
	clean := strings.TrimPrefix(path, "/")
	if clean == "" || clean == "." {
		ino, err := d.v.FindInode(apfsRootDirInoNum)
		if err == nil {
			d.pathCacheStore(path, cachedInode{oid: apfsRootDirInoNum, inode: ino})
		}
		return apfsRootDirInoNum, ino, err
	}
	parts := strings.Split(clean, "/")
	parentOID := uint64(apfsRootDirInoNum)
	var ino Inode
	for i, name := range parts {
		if name == "" {
			continue
		}
		drecKey := encodeDrecKey(parentOID, name)
		_, drecVal, err := d.v.lookupFSTreeFirst(drecKey)
		if err != nil {
			return 0, Inode{}, os.ErrNotExist
		}
		if len(drecVal) < 8 {
			return 0, Inode{}, fmt.Errorf("apfs: driver: drec val too short at %q", name)
		}
		childOID := uint64(drecVal[0]) | uint64(drecVal[1])<<8 | uint64(drecVal[2])<<16 | uint64(drecVal[3])<<24 |
			uint64(drecVal[4])<<32 | uint64(drecVal[5])<<40 | uint64(drecVal[6])<<48 | uint64(drecVal[7])<<56
		ino, err = d.v.FindInode(childOID)
		if err != nil {
			return 0, Inode{}, fmt.Errorf("apfs: driver: inode %d for %q: %w", childOID, name, err)
		}
		// All intermediate components must be directories.
		if i < len(parts)-1 && !ino.IsDir {
			return 0, Inode{}, fmt.Errorf("apfs: driver: %q is not a directory", name)
		}
		parentOID = childOID
	}
	d.pathCacheStore(path, cachedInode{oid: parentOID, inode: ino})
	return parentOID, ino, nil
}

// pathCacheLookup returns the cached entry for `path` if present.
// Safe for concurrent use: takes pathCacheMu for reading.
func (d *driver) pathCacheLookup(path string) (cachedInode, bool) {
	d.pathCacheMu.RLock()
	defer d.pathCacheMu.RUnlock()
	if d.pathCache == nil {
		return cachedInode{}, false
	}
	c, ok := d.pathCache[path]
	return c, ok
}

// pathCacheStore inserts an entry into the cache. Flushes the
// cache when it would exceed pathCacheCap to keep memory bounded.
// Safe for concurrent use: takes pathCacheMu for writing.
func (d *driver) pathCacheStore(path string, entry cachedInode) {
	d.pathCacheMu.Lock()
	defer d.pathCacheMu.Unlock()
	if d.pathCache == nil {
		d.pathCache = make(map[string]cachedInode, 64)
	}
	cap := d.pathCacheCap
	if cap == 0 {
		cap = pathCacheDefaultCap
	}
	if len(d.pathCache) >= cap {
		// Simple flush instead of LRU: keeps the implementation
		// trivial and the working set well within bounds for
		// disk-image workloads.
		d.pathCache = make(map[string]cachedInode, 64)
	}
	d.pathCache[path] = entry
}

// splitParent returns the parent directory's path and the leaf name
// for `path`. The root case ("/" or "") returns ("/", "").
func splitParent(path string) (parent, name string) {
	clean := strings.TrimPrefix(path, "/")
	if clean == "" {
		return "/", ""
	}
	if idx := strings.LastIndex(clean, "/"); idx >= 0 {
		return "/" + clean[:idx], clean[idx+1:]
	}
	return "/", clean
}

// Close releases the container (and the underlying mountpoint when
// the FS was opened via hdiutil-mount).
func (d *driver) Close() error {
	if d.mountpoint != "" {
		return detachImage(d.dev, d.mountpoint)
	}
	if d.c != nil {
		return d.c.Close()
	}
	return nil
}

// ReadFile reads the entire content of the file at `path`.
func (d *driver) ReadFile(path string) ([]byte, error) {
	if d.mountpoint != "" {
		return mountModeReadFile(d.mountpoint, path)
	}
	d.opMu.RLock()
	defer d.opMu.RUnlock()
	_, ino, err := d.resolvePath(path)
	if err != nil {
		return nil, err
	}
	if ino.IsDir {
		return nil, fmt.Errorf("apfs: %q is a directory", path)
	}
	return d.v.ReadFile(ino)
}

// ListDir returns the entries directly under `path`.
func (d *driver) ListDir(path string) ([]filesystem.DirEntry, error) {
	if d.mountpoint != "" {
		return mountModeListDir(d.mountpoint, path)
	}
	d.opMu.RLock()
	defer d.opMu.RUnlock()
	return d.listDirLocked(path)
}

// listDirLocked is the lock-already-held implementation of ListDir.
// Internal callers (recursive DeleteDir) avoid double-locking by
// invoking this directly.
func (d *driver) listDirLocked(path string) ([]filesystem.DirEntry, error) {
	_, ino, err := d.resolvePath(path)
	if err != nil {
		return nil, err
	}
	if !ino.IsDir {
		return nil, fmt.Errorf("apfs: %q is not a directory", path)
	}
	parentOID := ino.ID
	if parentOID == 0 {
		parentOID = apfsRootDirInoNum
	}
	var out []filesystem.DirEntry
	err = d.v.traverseFSTree(func(k, val []byte) error {
		oid, typ, err := jKeyHeader(k)
		if err != nil || oid != parentOID || typ != jTypeDirRec {
			return nil
		}
		name := drecNameFromKey(k)
		if name == "" {
			return nil
		}
		var childOID uint64
		if len(val) >= 8 {
			childOID = uint64(val[0]) | uint64(val[1])<<8 | uint64(val[2])<<16 | uint64(val[3])<<24 |
				uint64(val[4])<<32 | uint64(val[5])<<40 | uint64(val[6])<<48 | uint64(val[7])<<56
		}
		var ft uint8 = 8 // DT_REG
		if len(val) >= 18 {
			drecType := uint16(val[16]) | uint16(val[17])<<8
			ft = drecTypeToDT(drecType)
		}
		out = append(out, filesystem.NewDirEntry(childOID, name, ft))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Stat returns metadata for the path.
func (d *driver) Stat(path string) (filesystem.Stat, error) {
	if d.mountpoint != "" {
		return mountModeStat(d.mountpoint, path)
	}
	d.opMu.RLock()
	defer d.opMu.RUnlock()
	_, ino, err := d.resolvePath(path)
	if err != nil {
		return nil, err
	}
	mode := uint16(ino.Mode)
	if mode == 0 {
		if ino.IsDir {
			mode = 0o040755
		} else {
			mode = 0o100644
		}
	}
	return filesystem.NewStat(mode, ino.Size, ino.ID), nil
}

// WriteFile creates or overwrites a file at `path`.
func (d *driver) WriteFile(path string, data []byte, perm os.FileMode) error {
	if d.mountpoint != "" {
		return mountModeWriteFile(d.mountpoint, path, data, perm)
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	parent, name := splitParent(path)
	if name == "" {
		return fmt.Errorf("apfs: WriteFile: empty filename")
	}
	parentOID, _, err := d.resolvePath(parent)
	if err != nil {
		// Auto-create parent directories so the API matches the
		// previous test-driver conventiod.
		if mkErr := d.mkdirLocked(parent, 0o755); mkErr != nil {
			return fmt.Errorf("apfs: WriteFile: create parent %q: %w", parent, mkErr)
		}
		parentOID, _, err = d.resolvePath(parent)
		if err != nil {
			return err
		}
	}
	// If the file already exists, overwrite; otherwise create.
	drecKey := encodeDrecKey(parentOID, name)
	if _, drecVal, lookErr := d.v.lookupFSTreeFirst(drecKey); lookErr == nil && len(drecVal) >= 8 {
		fileOID := uint64(drecVal[0]) | uint64(drecVal[1])<<8 | uint64(drecVal[2])<<16 | uint64(drecVal[3])<<24 |
			uint64(drecVal[4])<<32 | uint64(drecVal[5])<<40 | uint64(drecVal[6])<<48 | uint64(drecVal[7])<<56
		// Reject overwriting a directory.
		ino, _ := d.v.FindInode(fileOID)
		if ino.IsDir {
			return fmt.Errorf("apfs: %q is a directory", path)
		}
		return d.v.OverwriteFile(fileOID, data)
	}
	_, err = d.v.CreateFile(parentOID, name, data)
	return err
}

// ReadLink resolves a symlink at `path`.
func (d *driver) ReadLink(path string) (string, error) {
	if d.mountpoint != "" {
		return mountModeReadLink(d.mountpoint, path)
	}
	d.opMu.RLock()
	defer d.opMu.RUnlock()
	_, ino, err := d.resolvePath(path)
	if err != nil {
		return "", err
	}
	// Symlinks in our APFS writer store the target as a
	// com.apple.fs.symlink xattr (Apple's convention).
	xs, err := d.v.ListXAttrs(ino)
	if err != nil {
		return "", err
	}
	for _, x := range xs {
		if x.Name == "com.apple.fs.symlink" {
			return string(x.EmbeddedValue), nil
		}
	}
	return "", fmt.Errorf("apfs: %q is not a symlink", path)
}

// Symlink creates a symbolic link at linkPath whose target is the literal
// string `target`. The parent of linkPath must exist; linkPath itself must
// not. Targets are stored verbatim as the com.apple.fs.symlink xattr (Apple's
// convention), mirroring what ReadLink decodes.
func (d *driver) Symlink(target, linkPath string) error {
	if d.mountpoint != "" {
		return os.Symlink(target, filepath.Join(d.mountpoint, linkPath))
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	parent, name := splitParent(linkPath)
	if name == "" {
		return fmt.Errorf("apfs: Symlink: empty link name")
	}
	parentOID, _, err := d.resolvePath(parent)
	if err != nil {
		return fmt.Errorf("apfs: Symlink: parent %q: %w", parent, err)
	}
	if _, _, e := d.v.lookupFSTreeFirst(encodeDrecKey(parentOID, name)); e == nil {
		return fmt.Errorf("apfs: Symlink: %q already exists", linkPath)
	}
	_, err = d.v.CreateSymlink(parentOID, name, target)
	return err
}

// Link adds a hardlink at newPath pointing at the same inode as oldPath. The
// source must not be a directory and newPath must not already exist.
func (d *driver) Link(oldPath, newPath string) error {
	if d.mountpoint != "" {
		return os.Link(filepath.Join(d.mountpoint, oldPath), filepath.Join(d.mountpoint, newPath))
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	srcOID, srcIno, err := d.resolvePath(oldPath)
	if err != nil {
		return fmt.Errorf("apfs: Link: source %q: %w", oldPath, err)
	}
	if srcIno.IsDir {
		return fmt.Errorf("apfs: Link: %q is a directory", oldPath)
	}
	parent, name := splitParent(newPath)
	if name == "" {
		return fmt.Errorf("apfs: Link: empty target name")
	}
	parentOID, _, err := d.resolvePath(parent)
	if err != nil {
		return fmt.Errorf("apfs: Link: parent %q: %w", parent, err)
	}
	if _, _, e := d.v.lookupFSTreeFirst(encodeDrecKey(parentOID, name)); e == nil {
		return fmt.Errorf("apfs: Link: %q already exists", newPath)
	}
	return d.v.CreateHardlink(srcOID, parentOID, name)
}

// Truncate resizes the regular file at path to newSize bytes (growing with
// implicit zero-fill, shrinking by dropping trailing data).
func (d *driver) Truncate(path string, newSize int64) error {
	if d.mountpoint != "" {
		return os.Truncate(filepath.Join(d.mountpoint, path), newSize)
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	if newSize < 0 {
		return fmt.Errorf("apfs: Truncate: negative size %d", newSize)
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	oid, ino, err := d.resolvePath(path)
	if err != nil {
		return err
	}
	if ino.IsDir {
		return fmt.Errorf("apfs: Truncate: %q is a directory", path)
	}
	if uint64(newSize) > ino.Size {
		// Grow: the engine's TruncateFile only bumps the logical size, which
		// would re-expose stale bytes left in an allocated block by a prior
		// shrink. POSIX truncate must zero-fill the new region, so rewrite the
		// content zero-padded to newSize instead. (Shrink/equal stays on the
		// efficient extent-trimming path below.)
		data, rerr := d.v.ReadFile(ino)
		if rerr != nil {
			return rerr
		}
		buf := make([]byte, newSize)
		copy(buf, data)
		return d.v.OverwriteFile(oid, buf)
	}
	return d.v.TruncateFile(oid, uint64(newSize))
}

// GrowTo expands the underlying container image to newSizeBytes.
func (d *driver) GrowTo(newSizeBytes int64) error {
	if d.mountpoint != "" {
		return fmt.Errorf("apfs: GrowTo: not supported in mount-backed mode")
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	return d.c.Grow(newSizeBytes)
}

// Resize changes the container image size in either direction; shrink is
// honoured only when the live data fits the smaller size.
func (d *driver) Resize(newSize int64) error {
	if d.mountpoint != "" {
		return fmt.Errorf("apfs: Resize: not supported in mount-backed mode")
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	return d.c.Resize(newSize)
}

// MkDir creates a directory at `path`. Idempotent (returns nil if
// it already exists as a directory).
func (d *driver) MkDir(path string, perm os.FileMode) error {
	if d.mountpoint != "" {
		return mountModeMkDir(d.mountpoint, path, perm)
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	return d.mkdirLocked(path, perm)
}

// mkdirLocked is the lock-already-held implementation of MkDir, so
// internal callers (WriteFile auto-creating parents, DeleteDir
// invoking ListDir recursively after a self-locked DeleteDir, etc.)
// can re-use the same logic without re-acquiring opMu.
func (d *driver) mkdirLocked(path string, perm os.FileMode) error {
	defer d.invalidatePathCache()
	clean := strings.TrimPrefix(path, "/")
	if clean == "" {
		return nil
	}
	parts := strings.Split(clean, "/")
	parentOID := uint64(apfsRootDirInoNum)
	for _, name := range parts {
		if name == "" {
			continue
		}
		drecKey := encodeDrecKey(parentOID, name)
		if _, drecVal, lookErr := d.v.lookupFSTreeFirst(drecKey); lookErr == nil && len(drecVal) >= 8 {
			childOID := uint64(drecVal[0]) | uint64(drecVal[1])<<8 | uint64(drecVal[2])<<16 | uint64(drecVal[3])<<24 |
				uint64(drecVal[4])<<32 | uint64(drecVal[5])<<40 | uint64(drecVal[6])<<48 | uint64(drecVal[7])<<56
			ino, ierr := d.v.FindInode(childOID)
			if ierr != nil {
				return ierr
			}
			if !ino.IsDir {
				return fmt.Errorf("apfs: %q exists and is not a directory", path)
			}
			parentOID = childOID
			continue
		}
		oid, err := d.v.CreateDirectory(parentOID, name, uint16(perm))
		if err != nil {
			return err
		}
		parentOID = oid
	}
	return nil
}

// DeleteFile removes the file at `path`.
func (d *driver) DeleteFile(path string) error {
	if d.mountpoint != "" {
		return mountModeDeleteFile(d.mountpoint, path)
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	return d.deleteFileLocked(path)
}

// deleteFileLocked is the lock-already-held implementation of DeleteFile.
func (d *driver) deleteFileLocked(path string) error {
	defer d.invalidatePathCache()
	parent, name := splitParent(path)
	if name == "" {
		return fmt.Errorf("apfs: DeleteFile: empty filename")
	}
	parentOID, _, err := d.resolvePath(parent)
	if err != nil {
		return err
	}
	return d.v.DeleteFile(parentOID, name)
}

// DeleteDir recursively removes a directory and its contents.
func (d *driver) DeleteDir(path string) error {
	if d.mountpoint != "" {
		return mountModeDeleteDir(d.mountpoint, path)
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	return d.deleteDirLocked(path)
}

// deleteDirLocked is the lock-already-held implementation of DeleteDir.
func (d *driver) deleteDirLocked(path string) error {
	defer d.invalidatePathCache()
	clean := strings.TrimPrefix(path, "/")
	if clean == "" {
		// Wipe everything under root.
		entries, err := d.listDirLocked("/")
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.FileType() == 4 { // DT_DIR
				if err := d.deleteDirLocked("/" + e.Name()); err != nil {
					return err
				}
			} else {
				if err := d.deleteFileLocked("/" + e.Name()); err != nil {
					return err
				}
			}
		}
		return nil
	}
	entries, err := d.listDirLocked(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		child := path + "/" + e.Name()
		if e.FileType() == 4 {
			if err := d.deleteDirLocked(child); err != nil {
				return err
			}
		} else {
			if err := d.deleteFileLocked(child); err != nil {
				return err
			}
		}
	}
	parent, name := splitParent(path)
	parentOID, _, err := d.resolvePath(parent)
	if err != nil {
		return err
	}
	return d.v.DeleteDirectory(parentOID, name)
}

// Rename moves the entry at `oldPath` to `newPath`.
func (d *driver) Rename(oldPath, newPath string) error {
	if d.mountpoint != "" {
		return mountModeRename(d.mountpoint, oldPath, newPath)
	}
	if d.c.w == nil {
		return ErrReadOnly
	}
	d.opMu.Lock()
	defer d.opMu.Unlock()
	defer d.invalidatePathCache()
	oldParent, oldName := splitParent(oldPath)
	newParent, newName := splitParent(newPath)
	if oldName == "" || newName == "" {
		return fmt.Errorf("apfs: Rename: empty filename")
	}
	oldParentOID, _, err := d.resolvePath(oldParent)
	if err != nil {
		return err
	}
	newParentOID, _, err := d.resolvePath(newParent)
	if err != nil {
		return err
	}
	return d.v.Rename(oldParentOID, oldName, newParentOID, newName)
}

// drecNameFromKey extracts the null-terminated name from a J_DIR_REC
// key. Hashed keys (case-insensitive volumes) carry a uint32
// name_len_and_hash at +8 followed by the name bytes; non-hashed
// keys carry a uint16 name_len at +8 followed by the name. Our
// writer uses hashed keys.
func drecNameFromKey(k []byte) string {
	if len(k) < 13 {
		return ""
	}
	// Skip j_key_t (8) + name_len_and_hash (4) = 12.
	rawName := k[12:]
	if i := bytesIndexByte(rawName, 0); i >= 0 {
		rawName = rawName[:i]
	}
	return string(rawName)
}

// drecTypeToDT maps an APFS drec_type to the POSIX DT_* constant
// used by the filesystem.DirEntry interface.
func drecTypeToDT(drecType uint16) uint8 {
	switch drecType {
	case drecTypeRegFile:
		return 8 // DT_REG
	case drecTypeDir:
		return 4 // DT_DIR
	case drecTypeSymlink:
		return 10 // DT_LNK
	case drecTypeFIFO:
		return 1 // DT_FIFO
	case drecTypeBLK:
		return 6 // DT_BLK
	case drecTypeCHR:
		return 2 // DT_CHR
	case drecTypeSOCK:
		return 12 // DT_SOCK
	}
	return 0 // DT_UNKNOWN
}
