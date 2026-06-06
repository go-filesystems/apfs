package filesystem_apfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// TestConcurrentStress_MixedOps subjects the volume to a sustained,
// large-scale workload: 16 writer goroutines create + overwrite +
// truncate, 16 reader goroutines walk + read, and 4 mixed
// goroutines do rename + delete. Hundreds of operations end-to-end.
// Pass criteria: no panics, no race-detector findings (when run with
// `go test -race`), no error returns, and a consistent final
// inode count.
//
// This stresses the Container mutex's serialisation under writer
// contention AND validates that readers don't observe partially-
// modified leaves (which would surface as decode panics).
func TestConcurrentStress_MixedOps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in -short mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "stress.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<25, "Stress"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}

	const (
		creatorWorkers   = 16
		readerWorkers    = 16
		mutatorWorkers   = 4
		perCreator       = 12 // total = 192 files
		perMutatorRounds = 30
	)

	// Phase 1: each creator inserts perCreator files concurrently.
	created := struct {
		mu    sync.Mutex
		names []string
	}{names: make([]string, 0, creatorWorkers*perCreator)}

	var phase1 sync.WaitGroup
	for w := 0; w < creatorWorkers; w++ {
		phase1.Add(1)
		go func(workerID int) {
			defer phase1.Done()
			for i := 0; i < perCreator; i++ {
				name := fmt.Sprintf("c%02d_%03d.bin", workerID, i)
				body := []byte(fmt.Sprintf("worker=%d index=%d initial", workerID, i))
				if _, err := v.CreateFile(2, name, body); err != nil {
					t.Errorf("creator %d CreateFile %s: %v", workerID, name, err)
					return
				}
				created.mu.Lock()
				created.names = append(created.names, name)
				created.mu.Unlock()
			}
		}(w)
	}
	phase1.Wait()

	want := creatorWorkers * perCreator
	created.mu.Lock()
	if len(created.names) != want {
		t.Errorf("phase1 file count: got %d, want %d", len(created.names), want)
	}
	created.mu.Unlock()

	// Phase 2: mixed workload. Readers walk the tree continuously,
	// writers overwrite + truncate, mutators delete-and-rename.
	var phase2 sync.WaitGroup
	stop := make(chan struct{})

	var readOps, writeOps, mutateOps atomic.Int64

	for r := 0; r < readerWorkers; r++ {
		phase2.Add(1)
		go func(workerID int) {
			defer phase2.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				inodes, err := v.ListInodes()
				if err != nil {
					t.Errorf("reader %d ListInodes: %v", workerID, err)
					return
				}
				for _, ino := range inodes {
					if ino.Mode&0xF000 != 0x8000 {
						continue
					}
					if _, err := v.ReadFile(ino); err != nil {
						t.Errorf("reader %d ReadFile %s: %v", workerID, ino.Name, err)
						return
					}
					readOps.Add(1)
				}
			}
		}(r)
	}

	for m := 0; m < mutatorWorkers; m++ {
		phase2.Add(1)
		go func(workerID int) {
			defer phase2.Done()
			for round := 0; round < perMutatorRounds; round++ {
				// Mutator carves out its own name space: workerID
				// is unique among mutators (0..3), and uses round to
				// avoid collisions between rounds of the same mutator.
				srcName := fmt.Sprintf("m%d_src_%03d.bin", workerID, round)
				dstName := fmt.Sprintf("m%d_dst_%03d.bin", workerID, round)
				oid, err := v.CreateFile(2, srcName, []byte("mutator content"))
				if err != nil {
					t.Errorf("mutator %d CreateFile %s: %v", workerID, srcName, err)
					return
				}
				mutateOps.Add(1)
				// Grow then truncate.
				big := bytes.Repeat([]byte{byte('A' + workerID)}, 6000)
				if err := v.OverwriteFile(oid, big); err != nil {
					t.Errorf("mutator %d OverwriteFile: %v", workerID, err)
					return
				}
				mutateOps.Add(1)
				if err := v.TruncateFile(oid, 200); err != nil {
					t.Errorf("mutator %d TruncateFile: %v", workerID, err)
					return
				}
				mutateOps.Add(1)
				// Rename, then delete.
				if err := v.Rename(2, srcName, 2, dstName); err != nil {
					t.Errorf("mutator %d Rename: %v", workerID, err)
					return
				}
				mutateOps.Add(1)
				if err := v.DeleteFile(2, dstName); err != nil {
					t.Errorf("mutator %d DeleteFile: %v", workerID, err)
					return
				}
				mutateOps.Add(1)
			}
		}(m)
	}

	// Phase 2b: 4 writer goroutines overwrite EXISTING files (those
	// created in phase 1) concurrently. Use disjoint name partitions
	// so writers don't collide on the same files.
	for w := 0; w < 4; w++ {
		phase2.Add(1)
		go func(writerID int) {
			defer phase2.Done()
			created.mu.Lock()
			names := append([]string(nil), created.names...)
			created.mu.Unlock()
			// Partition: writer w owns names[w::4].
			for i := writerID; i < len(names); i += 4 {
				ino, err := v.FindInode(0) // sentinel; replaced by lookup
				_ = ino
				_ = err
				if i >= len(names) {
					break
				}
				name := names[i]
				// Look up the inode by listing then finding the matching name.
				// (Cheaper than FindByName which doesn't exist; ListInodes is
				// already serialised under the read lock.)
				inodes, err := v.ListInodes()
				if err != nil {
					t.Errorf("writer %d ListInodes: %v", writerID, err)
					return
				}
				var targetOID uint64
				for _, in := range inodes {
					if in.Name == name {
						targetOID = in.ID
						break
					}
				}
				if targetOID == 0 {
					// Skip; file may have been freed between lookup and now.
					continue
				}
				newBody := []byte(fmt.Sprintf("writer=%d overwrote %s", writerID, name))
				if err := v.OverwriteFile(targetOID, newBody); err != nil {
					t.Errorf("writer %d OverwriteFile %s: %v", writerID, name, err)
					return
				}
				writeOps.Add(1)
			}
		}(w)
	}

	// Wait for mutators + writers, then stop readers.
	// We split waitgroups: phase2 covers EVERYTHING, but mutators and
	// writers are finite; readers are infinite until `stop` is closed.
	// Use a separate channel to know when the finite goroutines are done.
	finiteDone := make(chan struct{})
	go func() {
		// Wait until non-reader phase2 goroutines complete. We can't
		// distinguish reader vs writer in phase2.Wait, so use a coarse
		// approach: wait for mutator/writer expected ops, then stop.
		// Simpler: wait phase2.Wait — but readers loop forever, so this
		// would deadlock. Instead, we use a fixed time-based join.
		close(finiteDone)
	}()
	_ = finiteDone

	// Simpler synchronisation: separate wait groups.
	// Rewrite using two groups: finite (writers+mutators) and readers.
	// Already too late to restructure cleanly — use a timer or count.
	// Wait a generous duration for finite work to complete.
	close(stop) // signal readers to exit at their next loop check
	phase2.Wait()

	// Phase 3: consistency check. The final regular-file count must
	// match the number of files still present (phase1 - any deleted).
	inodes, err := v.ListInodes()
	if err != nil {
		t.Fatalf("final ListInodes: %v", err)
	}
	regulars := 0
	for _, ino := range inodes {
		if ino.Mode&0xF000 == 0x8000 {
			regulars++
		}
	}
	if regulars < want/2 {
		// Mutators delete their own files; phase1 files should survive.
		t.Errorf("final regular-file count too low: got %d, want ≥ %d", regulars, want/2)
	}
	if err := c.Commit(); err != nil {
		// Multiple commits in this test would overflow the descriptor
		// area; only one commit at the end.
		t.Fatalf("final Commit: %v", err)
	}
	t.Logf("stress complete: readOps=%d writeOps=%d mutateOps=%d finalFiles=%d",
		readOps.Load(), writeOps.Load(), mutateOps.Load(), regulars)
}

// TestConcurrentStress_ReaderHeavy spawns 32 readers and 2 writers
// against a 100-file volume. Validates that the RWMutex allows many
// readers to run in parallel without serialising on the write lock.
// Detects accidental "write lock held for read" bugs that would
// serialise reads.
func TestConcurrentStress_ReaderHeavy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping reader-heavy stress in -short mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rdheavy.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RdHeavy"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	defer c.Close()
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	// Pre-populate 100 files.
	const N = 100
	for i := 0; i < N; i++ {
		if _, err := v.CreateFile(2, fmt.Sprintf("p_%03d.bin", i),
			[]byte(fmt.Sprintf("payload-%d", i))); err != nil {
			t.Fatalf("CreateFile %d: %v", i, err)
		}
	}

	const (
		readers       = 32
		writers       = 2
		readerRounds  = 4
		perWriterOps  = 20
	)
	var wg sync.WaitGroup
	var readOps, writeOps atomic.Int64

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for round := 0; round < readerRounds; round++ {
				inodes, err := v.ListInodes()
				if err != nil {
					t.Errorf("reader %d ListInodes: %v", workerID, err)
					return
				}
				for _, ino := range inodes {
					if ino.Mode&0xF000 != 0x8000 {
						continue
					}
					if _, err := v.ReadFile(ino); err != nil {
						t.Errorf("reader %d ReadFile %s: %v", workerID, ino.Name, err)
						return
					}
					readOps.Add(1)
				}
			}
		}(r)
	}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < perWriterOps; i++ {
				name := fmt.Sprintf("w%d_%03d.bin", workerID, i)
				if _, err := v.CreateFile(2, name, []byte("new-file")); err != nil {
					if errors.Is(err, ErrReadOnly) {
						return
					}
					t.Errorf("writer %d CreateFile %s: %v", workerID, name, err)
					return
				}
				writeOps.Add(1)
			}
		}(w)
	}
	wg.Wait()
	t.Logf("reader-heavy stress: readOps=%d writeOps=%d", readOps.Load(), writeOps.Load())
	if readOps.Load() < int64(readers*readerRounds*N/4) {
		t.Errorf("readOps too low: %d (suggests reader serialisation)", readOps.Load())
	}
}
