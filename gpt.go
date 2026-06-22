package filesystem_apfs

// gpt.go adds GPT (GUID Partition Table) awareness to the apfs package's
// open path. Apple's `hdiutil create -fs APFS file.dmg` produces a raw
// image (`Class Name: CRawDiskImage`) whose first sector is a protective
// MBR, sector 1 holds an "EFI PART" GPT header, and the actual APFS NX
// superblock lives at the start of the Apple_APFS partition (typically
// LBA 2048 = byte offset 0x100000 = 1 MiB).
//
// Without GPT awareness, OpenContainer reads block 0 and rejects the
// image as "not an APFS container" because it sees the protective MBR.
// `OpenContainerAuto` adds a one-shot probe: read sector 1, check for
// the "EFI PART" magic, parse the partition table, find the entry whose
// type GUID starts with the Apple_APFS prefix, and wrap the underlying
// reader/writer so all subsequent ReadAt/WriteAt calls are offset by
// `partition_first_lba * 512`. The container still sees a flat APFS
// blob starting at "block 0".
//
// The wrapped backend keeps the same containerReader / containerWriter
// shape so the rest of the package doesn't need to know whether it's
// looking at a naked or partitioned image.

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-volumes/gpt"
)

// Apple_APFS partition type GUID is `7C3457EF-0000-11AA-AA11-00306543ECAC`
// in canonical form. On disk it's stored in mixed-endian "wire" format:
// the first three groups are little-endian, the rest big-endian.
//
//	canonical: 7C3457EF-0000-11AA-AA11-00306543ECAC
//	wire:      EF 57 34 7C 00 00 AA 11 AA 11 00 30 65 43 EC AC
var appleAPFSPartTypeGUID = [16]byte{
	0xEF, 0x57, 0x34, 0x7C,
	0x00, 0x00,
	0xAA, 0x11,
	0xAA, 0x11,
	0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
}

// gptSectorSize is the LBA size GPT uses on every modern image (4Kn
// drives use 4096 but those are rare; hdiutil emits 512). We hard-code
// 512 here — APFS tooling on macOS does the same.
const gptSectorSize = 512

// findAPFSPartitionOffset returns the byte offset of the Apple_APFS
// partition's first sector, or 0 when the image is not GPT-wrapped (no
// partition table at all). It delegates to the shared, hardened
// go-volumes/gpt parser, which validates every offset/length against the
// device size and never panics on a malicious table.
//
// Resolution order, preserving the historical fallback behaviour:
//   - no partition table (gpt.ErrNoTable) → offset 0 (naked APFS image)
//   - an Apple_APFS partition exists       → its StartOffset
//   - a table exists but has no Apple_APFS  → error (don't read garbage)
//
// f is the opened image; its size (via Stat) bounds the parser.
func findAPFSPartitionOffset(f *os.File) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("apfs: gpt: stat image: %w", err)
	}
	deviceSize := info.Size()
	if deviceSize <= 0 {
		// Empty / unstattable image: behave like a naked container.
		return 0, nil
	}
	part, err := gpt.ByType(f, deviceSize, gpt.AppleAPFSGUID)
	if err == nil {
		return part.StartOffset, nil
	}
	if errors.Is(err, gpt.ErrNoTable) {
		// Not partitioned at all: naked APFS image at offset 0.
		return 0, nil
	}
	if errors.Is(err, gpt.ErrNotFound) {
		// A partition table exists but carries no Apple_APFS entry. Surface
		// a clear error rather than reading garbage at offset 0.
		return 0, fmt.Errorf("apfs: gpt: image is partitioned but has no Apple_APFS partition")
	}
	// Malformed table (truncated header, bad geometry, …): treated as an
	// error so we never read past a corrupt table.
	return 0, fmt.Errorf("apfs: gpt: %w", err)
}

// offsetReader wraps a containerReader, adding `offset` to every ReadAt
// argument. Used to make a partition inside a GPT'd image look flat to
// the rest of the parser.
type offsetReader struct {
	inner  containerReader
	offset int64
}

func (o *offsetReader) ReadAt(p []byte, off int64) (int, error) {
	return o.inner.ReadAt(p, off+o.offset)
}

// offsetWriter wraps a containerWriter, adding `offset` to every WriteAt
// argument. Returned only when the underlying inner satisfies
// containerWriter; read-only backends are unaffected.
type offsetWriter struct {
	*offsetReader
	innerW containerWriter
}

func (o *offsetWriter) WriteAt(p []byte, off int64) (int, error) {
	return o.innerW.WriteAt(p, off+o.offsetReader.offset)
}

// OpenContainerAuto opens an APFS container at path read-only, auto-
// detecting whether the file is naked APFS (NX SB at offset 0) or
// GPT-wrapped (NX SB inside the Apple_APFS partition). Use this when
// you don't know up-front whether you're looking at the output of our
// `FormatContainer` (naked) or Apple's `hdiutil create -fs APFS` (GPT).
func OpenContainerAuto(path string) (*Container, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("apfs: open %s: %w", path, err)
	}
	off, err := findAPFSPartitionOffset(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	var r containerReader = f
	if off != 0 {
		r = &offsetReader{inner: f, offset: off}
	}
	c, err := openContainerFrom(r, f.Close)
	if err != nil {
		f.Close()
		return nil, err
	}
	c.w = nil
	return c, nil
}

// OpenContainerRWAuto is OpenContainerAuto with read+write capability.
// When the image is GPT-wrapped, both reads and writes are offset into
// the Apple_APFS partition; the GPT header and protective MBR are
// untouched (writes outside the APFS partition would corrupt them).
func OpenContainerRWAuto(path string) (*Container, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("apfs: rw open %s: %w", path, err)
	}
	off, err := findAPFSPartitionOffset(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	var r containerReader = f
	var w containerWriter = f
	if off != 0 {
		or := &offsetReader{inner: f, offset: off}
		r = or
		w = &offsetWriter{offsetReader: or, innerW: f}
	}
	c, err := openContainerFrom(r, f.Close)
	if err != nil {
		f.Close()
		return nil, err
	}
	c.w = w
	return c, nil
}
