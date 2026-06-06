package filesystem_apfs

// read_streaming.go — random-access readers for file contents and
// stream xattrs that don't buffer the whole payload.
//
// `ReadFile` / `ReadXAttrStream` already exist but allocate a slice
// of the full logical size, then concatenate every extent into it.
// That's fine for small files but wastes memory on multi-MiB files
// (boot images, kernels, archive contents). The two functions in
// this file expose `io.ReaderAt` views over the same data so the
// caller can stream a window without loading the whole payload.
//
// Sparse holes (gaps between extents, and any trailing zero region
// implied by `inode.Size > sum(extent.length)`) are filled with
// zeros without consuming disk I/O — matching the behaviour of the
// non-streaming `ReadFile`.

import (
	"fmt"
	"io"
	"sort"
)

// extentReaderAt implements `io.ReaderAt` over a sorted list of
// physical extents that map a contiguous logical address range
// `[0, totalSize)`. Reads past `totalSize` return io.EOF; reads
// that span a sparse hole return zeros for that portion.
type extentReaderAt struct {
	r         io.ReaderAt
	blockSize uint64
	extents   []containerExtent // sorted by logicalOffset, no overlaps
	totalSize uint64
}

// ReadAt copies bytes from the logical address `off` into p. Behaves
// like io.ReaderAt: returns the number of bytes copied + an error;
// io.EOF when off ≥ totalSize OR the read window extends past the end.
func (r *extentReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("apfs: extentReaderAt: negative offset %d", off)
	}
	if uint64(off) >= r.totalSize {
		return 0, io.EOF
	}
	// Clamp the read window to totalSize so we never serve bytes past EOF.
	want := uint64(len(p))
	if uint64(off)+want > r.totalSize {
		want = r.totalSize - uint64(off)
	}
	dst := p[:want]
	// Zero-fill upfront — the extent loop will overwrite the regions
	// covered by real extents and leave sparse holes / trailing zeros
	// untouched.
	for i := range dst {
		dst[i] = 0
	}
	hi := uint64(off) + want
	for _, ext := range r.extents {
		extEnd := ext.logicalOffset + ext.length
		if extEnd <= uint64(off) {
			continue // extent fully before window
		}
		if ext.logicalOffset >= hi {
			break // extent fully past window (extents are sorted)
		}
		// Overlap region in logical coordinates:
		lo := ext.logicalOffset
		if lo < uint64(off) {
			lo = uint64(off)
		}
		hi2 := extEnd
		if hi2 > hi {
			hi2 = hi
		}
		if hi2 <= lo {
			continue
		}
		// Map to physical: extent starts at physBlock * blockSize;
		// the position within the extent is (lo - ext.logicalOffset).
		physOff := int64(ext.physBlock*r.blockSize) + int64(lo-ext.logicalOffset)
		dstStart := lo - uint64(off)
		dstEnd := hi2 - uint64(off)
		if _, err := r.r.ReadAt(dst[dstStart:dstEnd], physOff); err != nil {
			// Short reads from the underlying device are unexpected
			// (extents always map to allocated blocks in our writer).
			return int(dstStart), fmt.Errorf("apfs: extentReaderAt: read at paddr %d: %w",
				ext.physBlock, err)
		}
	}
	if want < uint64(len(p)) {
		// We delivered fewer bytes than requested because the window
		// extended past totalSize — signal EOF per io.ReaderAt contract.
		return int(want), io.EOF
	}
	return int(want), nil
}

// FileReaderAt returns an io.ReaderAt that streams the bytes of the
// regular file at `inode` on demand without buffering the whole
// payload. Bounded to `inode.Size`: reads past the end return
// `io.EOF`. Sparse holes return zeros without consuming I/O.
//
// The returned reader holds a snapshot of the inode's extent list
// at the time of the call; subsequent writes to the file will not
// be visible.
//
// Returns an error if `inode` is a directory.
func (v *Volume) FileReaderAt(inode Inode) (io.ReaderAt, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	if inode.IsDir {
		return nil, fmt.Errorf("apfs: FileReaderAt on directory %q", inode.Name)
	}
	bs := uint64(v.c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	sorted := make([]containerExtent, len(inode.dataExtents))
	copy(sorted, inode.dataExtents)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].logicalOffset < sorted[j].logicalOffset
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i].logicalOffset < sorted[i-1].logicalOffset+sorted[i-1].length {
			return nil, fmt.Errorf("apfs: FileReaderAt: overlapping extents at logical %d",
				sorted[i].logicalOffset)
		}
	}
	return &extentReaderAt{
		r:         v.c.r,
		blockSize: bs,
		extents:   sorted,
		totalSize: inode.Size,
	}, nil
}

// XAttrStreamReaderAt returns an io.ReaderAt that streams the bytes
// of the stream-extent xattr `x` on demand. Bounded to `x.StreamSize`.
// For embedded xattrs (no stream id) the returned reader wraps
// `x.EmbeddedValue` via `bytes.Reader`-like semantics: a single
// in-memory copy with the same ReaderAt interface.
func (v *Volume) XAttrStreamReaderAt(x XAttr) (io.ReaderAt, error) {
	v.c.mu.RLock()
	defer v.c.mu.RUnlock()
	if x.Flags&xattrFlagDataStream == 0 {
		// Embedded: tiny payload already in memory. Stream from it.
		return &bytesReaderAt{buf: append([]byte(nil), x.EmbeddedValue...)}, nil
	}
	if x.StreamID == 0 {
		return nil, fmt.Errorf("apfs: XAttrStreamReaderAt: stream xattr %q has zero stream id", x.Name)
	}
	var extents []containerExtent
	visit := func(k, val []byte) error {
		oid, typ, err := jKeyHeader(k)
		if err != nil || typ != jTypeFileExt || oid != x.StreamID {
			return nil
		}
		if ext, ok := decodeFileExtent(k, val); ok {
			extents = append(extents, ext)
		}
		return nil
	}
	if err := v.traverseFSTree(visit); err != nil {
		return nil, err
	}
	sort.Slice(extents, func(i, j int) bool {
		return extents[i].logicalOffset < extents[j].logicalOffset
	})
	for i := 1; i < len(extents); i++ {
		if extents[i].logicalOffset < extents[i-1].logicalOffset+extents[i-1].length {
			return nil, fmt.Errorf("apfs: XAttrStreamReaderAt: overlapping extents at logical %d",
				extents[i].logicalOffset)
		}
	}
	bs := uint64(v.c.sb.blockSize)
	if bs == 0 {
		bs = 4096
	}
	return &extentReaderAt{
		r:         v.c.r,
		blockSize: bs,
		extents:   extents,
		totalSize: x.StreamSize,
	}, nil
}

// bytesReaderAt is a trivial io.ReaderAt over a fixed byte slice.
// Used as the streaming view of an embedded xattr (whose payload is
// already in memory) so XAttrStreamReaderAt has a uniform return
// type regardless of stream-vs-embedded.
type bytesReaderAt struct {
	buf []byte
}

func (b *bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("apfs: bytesReaderAt: negative offset %d", off)
	}
	if off >= int64(len(b.buf)) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
