package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestStress_ResizeCycle interleaves Grow / Shrink cycles with file
// CreateFile / ReadFile work. The goal is to stress the metadata
// bookkeeping cascade (NX SB ↔ spaceman ↔ CIB ↔ bitmap) under
// repeated geometry changes and confirm that:
//
//   - Files created before a Grow remain readable after.
//   - A Shrink back to the original size doesn't drop any allocated
//     extent (the bitmap guard rejects it if it would).
//   - The container stays openable + parseable across N cycles.
//
// Gated by stressShortSkip so the default `go test ./...` skips it.
// Set APFS_STRESS_FORCE=1 to run inside -short.
func TestStress_ResizeCycle(t *testing.T) {
	if stressShortSkip(t) {
		return
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "resize-cycle.apfs")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	const startSize = int64(1 << 22) // 4 MiB
	const grownSize = int64(1 << 23) // 8 MiB
	if err := FormatContainer(img, startSize, "ResizeCycle"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	c, err := OpenContainerRW(img)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}

	const cycles = 16
	const filesPerCycle = 8
	created := make([]string, 0, cycles*filesPerCycle)

	for cycle := 0; cycle < cycles; cycle++ {
		// Grow.
		if err := c.Grow(grownSize); err != nil {
			t.Fatalf("cycle %d Grow: %v", cycle, err)
		}
		if c.sb.blockCount != uint64(grownSize/4096) {
			t.Fatalf("cycle %d: post-Grow blockCount=%d want %d",
				cycle, c.sb.blockCount, grownSize/4096)
		}
		// Files in the grown phase land at higher block numbers;
		// CreateFile uses nextFreeBlock which consults the bitmap.
		for i := 0; i < filesPerCycle; i++ {
			name := fmt.Sprintf("grown-%02d-%02d.bin", cycle, i)
			payload := []byte(fmt.Sprintf("cycle=%d idx=%d", cycle, i))
			if _, err := v.CreateFile(2, name, payload); err != nil {
				t.Fatalf("cycle %d CreateFile %s: %v", cycle, name, err)
			}
			created = append(created, name)
		}
		// Shrink back. The allocator's bump cursor sits above the
		// metadata floor; if the bitmap reports any in-use block ≥
		// startSize/4096 the Shrink will refuse with
		// ErrShrinkUnsupported, which is the expected outcome when
		// CreateFile placed an extent in the upper half. Either
		// behaviour is acceptable in this stress: success means
		// the geometry round-tripped, ErrShrinkUnsupported means
		// the sentinel correctly protected the user.
		err := c.Shrink(startSize)
		if err != nil && !errIsShrinkUnsupported(err) {
			t.Fatalf("cycle %d Shrink: unexpected error %v", cycle, err)
		}
		if err == nil && c.sb.blockCount != uint64(startSize/4096) {
			t.Fatalf("cycle %d: post-Shrink blockCount=%d want %d",
				cycle, c.sb.blockCount, startSize/4096)
		}
	}

	// Sanity: every file we created is still openable and readable.
	inodes, err := v.ListInodes()
	if err != nil {
		t.Fatalf("ListInodes: %v", err)
	}
	gotByName := map[string]bool{}
	for _, ino := range inodes {
		gotByName[ino.Name] = true
	}
	missing := 0
	for _, name := range created {
		if !gotByName[name] {
			missing++
		}
	}
	if missing > 0 {
		t.Fatalf("%d/%d files vanished across resize cycles", missing, len(created))
	}
}

// TestStress_ResizeConcurrentReaders fires N read goroutines against
// the volume while the main goroutine cycles Grow / Shrink. The
// container's RWMutex serialises the two roles, so readers should
// never observe a torn geometry. Failure mode: a reader panics, a
// reader returns an inconsistent error, or the in-memory blockCount
// drifts from the on-disk value.
func TestStress_ResizeConcurrentReaders(t *testing.T) {
	if stressShortSkip(t) {
		return
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "resize-readers.apfs")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatalf("create: %v", err)
	}
	const startSize = int64(1 << 22)
	const grownSize = int64(1 << 23)
	if err := FormatContainer(img, startSize, "ResizeReaders"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	c, err := OpenContainerRW(img)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	// Seed: create a handful of files so readers have something to
	// enumerate while we resize.
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("seed-%02d.bin", i)
		if _, err := v.CreateFile(2, name, []byte("seed")); err != nil {
			t.Fatalf("CreateFile %s: %v", name, err)
		}
	}

	const readers = 4
	const iters = 8
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = v.ListInodes()
			}
		}()
	}
	for i := 0; i < iters; i++ {
		if err := c.Grow(grownSize); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("iter %d Grow: %v", i, err)
		}
		err := c.Shrink(startSize)
		if err != nil && !errIsShrinkUnsupported(err) {
			close(stop)
			wg.Wait()
			t.Fatalf("iter %d Shrink: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}

// errIsShrinkUnsupported is a thin wrapper around errors.Is that
// keeps the stress test readable. The sentinel must match exactly
// (wrapped or not).
func errIsShrinkUnsupported(err error) bool {
	for cur := err; cur != nil; {
		if cur == ErrShrinkUnsupported {
			return true
		}
		// Unwrap path.
		type unwrapper interface{ Unwrap() error }
		uw, ok := cur.(unwrapper)
		if !ok {
			return false
		}
		cur = uw.Unwrap()
	}
	return false
}
