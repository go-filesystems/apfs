package filesystem_apfs

// driver_concurrency_test.go — regression test for the driver-level
// pathCache race that previously panicked with
// "concurrent map writes" under parallel WriteFile/ReadFile calls.
// The fix wraps pathCache with an RWMutex and serialises every public
// driver method with d.opMu (RLock for reads, Lock for writes), so
// the FS-tree root pointers and the in-memory pathCache map are no
// longer observed mid-mutation by another goroutine.

import (
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// TestDriverPathCacheConcurrency hammers WriteFile / ReadFile from
// multiple goroutines and asserts the driver never panics, never
// returns mismatched data, and never deadlocks. Run with -race to
// catch any residual fine-grained races on the cache or rootNode
// pointer fields.
func TestDriverPathCacheConcurrency(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "concurrency.apfs")
	fs, err := Format(img, 1<<26, FormatConfig{Label: "DrvConc"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	const workers = 16
	const opsPerWorker = 60
	var ops, errs atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				name := fmt.Sprintf("/w%02d_%04d.bin", id, i)
				want := fmt.Sprintf("worker=%d seq=%d", id, i)
				if err := fs.WriteFile(name, []byte(want), 0o644); err != nil {
					errs.Add(1)
					continue
				}
				got, err := fs.ReadFile(name)
				if err != nil {
					errs.Add(1)
					continue
				}
				if string(got) != want {
					// Data-loss signature — fail hard from the test
					// goroutine.
					t.Errorf("mismatch worker=%d seq=%d: got %q want %q", id, i, string(got), want)
					return
				}
				ops.Add(1)
			}
		}(w)
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	if ops.Load() == 0 {
		t.Fatalf("no operations completed (errs=%d)", errs.Load())
	}
	t.Logf("driver concurrency: workers=%d ops=%d errs=%d", workers, ops.Load(), errs.Load())
}

// TestDriverPathCacheConcurrentLookup mixes ReadFile (no mutation),
// Stat, ListDir, and WriteFile so the RWMutex covers both readers and
// writers simultaneously. The directory layout is created up front to
// give every goroutine a stable workload.
func TestDriverPathCacheConcurrentLookup(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "concurrent_lookup.apfs")
	fs, err := Format(img, 1<<25, FormatConfig{Label: "DrvLookup"})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	const N = 32
	if err := fs.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	for i := 0; i < N; i++ {
		if err := fs.WriteFile(fmt.Sprintf("/d/seed_%02d", i),
			[]byte(fmt.Sprintf("s-%d", i)), 0o644); err != nil {
			t.Fatalf("seed write %d: %v", i, err)
		}
	}

	const workers = 12
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				switch (id + i) % 4 {
				case 0:
					_, _ = fs.ReadFile(fmt.Sprintf("/d/seed_%02d", i%N))
				case 1:
					_, _ = fs.Stat(fmt.Sprintf("/d/seed_%02d", i%N))
				case 2:
					_, _ = fs.ListDir("/d")
				case 3:
					_ = fs.WriteFile(fmt.Sprintf("/d/w_%02d_%03d", id, i), []byte("x"), 0o644)
				}
			}
		}(w)
	}
	wg.Wait()
}
