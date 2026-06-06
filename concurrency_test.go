package filesystem_apfs

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestConcurrent_CreateAndRead spawns multiple writer goroutines that
// CreateFile concurrently and reader goroutines that ListInodes /
// ReadFile concurrently. Without the Container mutex the race
// detector flags writes to v.rootNode / v.allocCursor /
// v.c.allocOIDCursor / v.c.sb.* and the writers may produce a
// corrupted FS-tree. Run with `go test -race -run TestConcurrent`.
func TestConcurrent_CreateAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<24, "Concurrent"); err != nil {
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
		writers   = 4
		readers   = 4
		perWriter = 25
	)

	var writerWG sync.WaitGroup
	var readerWG sync.WaitGroup
	stopReaders := make(chan struct{})

	for w := 0; w < writers; w++ {
		writerWG.Add(1)
		go func(workerID int) {
			defer writerWG.Done()
			for i := 0; i < perWriter; i++ {
				name := fmt.Sprintf("w%d_%03d.bin", workerID, i)
				body := []byte(fmt.Sprintf("worker=%d index=%d", workerID, i))
				if _, err := v.CreateFile(2, name, body); err != nil {
					t.Errorf("worker %d CreateFile %s: %v", workerID, name, err)
					return
				}
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func(workerID int) {
			defer readerWG.Done()
			for {
				select {
				case <-stopReaders:
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
				}
			}
		}(r)
	}

	writerWG.Wait()
	close(stopReaders)
	readerWG.Wait()

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
	if regulars != writers*perWriter {
		t.Errorf("final file count: got %d, want %d", regulars, writers*perWriter)
	}
}

// TestConcurrent_RenameAndDelete runs concurrent Rename and DeleteFile
// operations on disjoint file sets. Verifies the lock prevents the
// classic "modify a leaf while another goroutine reads it" race AND
// that the cross-method call Rename→deleteFileLocked (overwrite path)
// doesn't self-deadlock.
func TestConcurrent_RenameAndDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rendelconc.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "RenDelConc"); err != nil {
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

	const N = 20
	for i := 0; i < N; i++ {
		if _, err := v.CreateFile(2, fmt.Sprintf("src_%02d", i), []byte("src")); err != nil {
			t.Fatalf("CreateFile src %d: %v", i, err)
		}
		if _, err := v.CreateFile(2, fmt.Sprintf("dst_%02d", i), []byte("dst")); err != nil {
			t.Fatalf("CreateFile dst %d: %v", i, err)
		}
	}

	var wg sync.WaitGroup
	// Goroutine 1: overwrite-rename src_[0..N/2) → dst_[0..N/2). This
	// exercises the cross-call path Rename → deleteFileLocked under
	// the same lock acquisition.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < N/2; i++ {
			if err := v.Rename(2, fmt.Sprintf("src_%02d", i), 2, fmt.Sprintf("dst_%02d", i)); err != nil {
				t.Errorf("Rename src_%02d → dst_%02d: %v", i, i, err)
				return
			}
		}
	}()
	// Goroutine 2: delete src_[N/2..N).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := N / 2; i < N; i++ {
			if err := v.DeleteFile(2, fmt.Sprintf("src_%02d", i)); err != nil {
				t.Errorf("DeleteFile src_%02d: %v", i, err)
				return
			}
		}
	}()
	wg.Wait()

	for i := 0; i < N; i++ {
		// All src_* names must be gone.
		if _, _, err := v.lookupFSTreeFirst(encodeDrecKey(2, fmt.Sprintf("src_%02d", i))); err == nil {
			t.Errorf("src_%02d still present after concurrent rename+delete", i)
		}
	}
}
