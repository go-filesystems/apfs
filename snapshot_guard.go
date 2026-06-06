package filesystem_apfs

// snapshot_guard.go: prevents writes to a volume after a snapshot has
// been taken, so the snapshot's frozen view stays consistent.
//
// Background: APFS snapshots freeze a point-in-time view of the volume
// (frozen APSB + the trees it references at that xid). To preserve
// the frozen view across subsequent writes, those writes must
// COPY-ON-WRITE every modified tree node — allocate a fresh paddr,
// add a volume OMAP entry at the new xid, leave the old paddr alone.
//
// Our writer currently mutates trees IN PLACE at the same paddr
// (ergonomic for single-volume short-lived workflows, but corrupts
// snapshots). Until the in-place writers are converted to CoW, we
// REFUSE writes against a volume that has snapshots — `ErrHasSnapshot`
// surfaces with a clear message instead of silently corrupting the
// snapshot's view.
//
// Removing the snapshots via `Volume.DeleteSnapshot` lifts the guard.
// As an alternative, callers can
// explicitly suppress the guard with `Volume.SetSuppressSnapshotGuard`
// when they accept that the snapshot view will be invalidated — most
// callers should not, but this lets test fixtures that intentionally
// modify snapshotted volumes continue to work.

import (
	"errors"
)

// ErrHasSnapshot is returned by every writer-side entry point on a
// volume whose APSB reports `apfs_num_snapshots > 0`. The frozen
// snapshot view shares physical blocks (FS-tree root, extent-ref
// tree, etc.) with the live volume, so an in-place mutation would
// corrupt the snapshot. Until copy-on-write is implemented for every
// mutating path, callers must remove the snapshot first OR explicitly
// suppress the guard via `Volume.SetSuppressSnapshotGuard(true)`.
var ErrHasSnapshot = errors.New("apfs: refusing to mutate a volume with active snapshots (would corrupt the frozen view)")

// SetSuppressSnapshotGuard toggles the snapshot-write guard on this
// volume handle. The default (false) is the safe choice: writers
// return ErrHasSnapshot when num_snapshots > 0. Setting to true tells
// the package "I know what I'm doing — proceed with in-place writes
// even if it corrupts the snapshot". Used by test fixtures that need
// post-snapshot writes for byte-diff diagnostics.
func (v *Volume) SetSuppressSnapshotGuard(on bool) {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	v.suppressSnapshotGuard = on
}

// checkSnapshotGuard is the writer-side preflight: returns
// ErrHasSnapshot when the volume has snapshots and the guard is
// enabled. Called at the top of every mutating volume-level entry
// point (CreateFile, CreateDirectory, Rename, DeleteFile, ...).
func (v *Volume) checkSnapshotGuard() error {
	if v.apsb == nil {
		return nil
	}
	if v.apsb.numSnapshots == 0 || v.suppressSnapshotGuard {
		return nil
	}
	return ErrHasSnapshot
}
