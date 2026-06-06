// fuzz_test.go — Go-native fuzz targets for the APFS parser surface.
//
// The fuzzer exercises Open() against mutated container images. Pass
// criteria: never panic, never block forever, never OOM. Memory caps
// are enforced by the fuzz harness (Go's runtime cgo OOM guard) — we
// also reject inputs larger than 4 MiB so a single corpus entry can't
// itself OOM.
//
// Run with:
//
//	go test -fuzz=FuzzOpen -fuzztime=10m
//
// `go test ./...` (no -fuzz) only executes the seed corpus once and
// completes in a few hundred milliseconds — safe in the default flow.

package filesystem_apfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// FuzzOpen feeds mutated byte slices to Open() via a temp file and
// asserts the call returns (success or any error) without panicking.
//
// Seed corpus:
//   - a tiny valid empty container (built fresh per test invocation)
//   - 4 boundary-byte slices (empty / 1 byte / "APFS" magic / all-zero)
//
// The fuzzer mutates these. The parser MUST classify random bytes as
// non-APFS (returning ErrNoHeader or a parse error), never trip an
// out-of-bounds panic. Note: we open through Open(), which on darwin
// falls through to hdiutil-attach when the file isn't a real APFS
// container — we make sure the file extension doesn't trigger hdiutil
// by writing into a temp dir under our control.
func FuzzOpen(f *testing.F) {
	// Build a single valid seed image to base the corpus on.
	seedDir := f.TempDir()
	seedImg := filepath.Join(seedDir, "seed.apfs")
	if err := os.WriteFile(seedImg, nil, 0o600); err != nil {
		f.Fatalf("seed: create: %v", err)
	}
	if err := FormatContainer(seedImg, 1<<20, "FuzzSeed"); err != nil {
		f.Fatalf("seed: FormatContainer: %v", err)
	}
	seedBytes, err := os.ReadFile(seedImg)
	if err != nil {
		f.Fatalf("seed: read: %v", err)
	}
	f.Add(seedBytes)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte("APFS"))
	f.Add(bytes.Repeat([]byte{0x00}, 4096))
	// One slightly-corrupted variant: flip the magic.
	if len(seedBytes) >= 36 {
		corrupt := append([]byte(nil), seedBytes...)
		corrupt[32] ^= 0xFF
		f.Add(corrupt)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap input size so a single mutation can't OOM the harness.
		const maxInput = 4 * 1024 * 1024
		if len(data) > maxInput {
			data = data[:maxInput]
		}
		// Write to a temp file Open() will accept. On darwin Open() may
		// fall back to hdiutil-attach when the pure-Go parser rejects
		// the input; we don't want that to spawn external processes
		// during fuzzing, so we use OpenContainerFromBackend on a
		// *bytes.Reader-like wrapper instead. That path is the one
		// exposed to untrusted images in production via OpenFDE and
		// related entry points.
		br := &readOnlyByteBackend{data: data}
		// MUST NOT panic regardless of input.
		c, err := OpenContainerFromBackend(br)
		if err != nil {
			return // parser correctly rejected the input
		}
		// Accepted as a container — try to open the first volume too.
		// This drives the FS-tree decoder, which is the other major
		// untrusted-input surface.
		defer c.Close()
		v, verr := c.OpenVolume(0)
		if verr != nil {
			return
		}
		// ListInodes pulls every inode record; that's the broadest
		// invocation of the record decoders.
		_, _ = v.ListInodes()
	})
}

// readOnlyByteBackend exposes a byte slice via the containerReader
// (ReadAt only) interface, with bounds checks that turn out-of-range
// reads into io.EOF-equivalent behaviour. Used by FuzzOpen so we don't
// touch the filesystem on every iteration.
type readOnlyByteBackend struct {
	data []byte
}

func (b *readOnlyByteBackend) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b.data)) {
		// Behave like an unaligned EOF: many readers treat short reads
		// as io.ErrUnexpectedEOF. Returning 0 + the standard sentinel
		// here is more idiomatic than a custom error.
		return 0, errShortRead
	}
	n := copy(p, b.data[off:])
	if n < len(p) {
		return n, errShortRead
	}
	return n, nil
}

// errShortRead is reused across all short-read returns from the fuzz
// backend so the driver sees a consistent error identity.
var errShortRead = errors.New("apfs-fuzz: short read")
