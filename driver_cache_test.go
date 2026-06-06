package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPathCache_HitAfterRead verifies that resolvePath populates
// the cache on first call, and that subsequent reads find the
// entry. We probe the cache through the unexported field directly
// to avoid coupling the test to behavioural side-effects.
func TestPathCache_HitAfterRead(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "cache.apfs")
	fs, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.WriteFile("/sub/file.txt", []byte("body"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	d := fs.(*driver)
	// After WriteFile (a mutating op), the cache must be empty.
	if got := len(d.pathCache); got != 0 {
		t.Errorf("post-write cache size: got %d, want 0", got)
	}
	// First read populates the cache.
	if _, err := fs.Stat("/sub/file.txt"); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := len(d.pathCache); got == 0 {
		t.Errorf("post-Stat cache size: got 0, want ≥ 1")
	}
	// Second read hits the cache (no fresh tree walk). We can't
	// directly observe that, but the cache size should not change
	// for an already-cached path.
	sizeBefore := len(d.pathCache)
	if _, err := fs.Stat("/sub/file.txt"); err != nil {
		t.Fatalf("Stat (cached): %v", err)
	}
	if got := len(d.pathCache); got != sizeBefore {
		t.Errorf("repeat Stat grew cache: %d → %d", sizeBefore, got)
	}
}

// TestPathCache_InvalidatedByMutation verifies a write drops every
// cached entry.
func TestPathCache_InvalidatedByMutation(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "inv.apfs")
	fs, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.WriteFile("/a.txt", []byte("a"), 0o644); err != nil {
		t.Fatalf("WriteFile a: %v", err)
	}
	if _, err := fs.Stat("/a.txt"); err != nil {
		t.Fatalf("Stat a: %v", err)
	}
	d := fs.(*driver)
	if len(d.pathCache) == 0 {
		t.Fatal("cache empty after read")
	}
	// Any mutation must clear the cache.
	if err := fs.WriteFile("/b.txt", []byte("b"), 0o644); err != nil {
		t.Fatalf("WriteFile b: %v", err)
	}
	if got := len(d.pathCache); got != 0 {
		t.Errorf("post-write cache: got %d, want 0", got)
	}
}

// TestPathCache_BoundedSize verifies the cache flushes when it
// hits pathCacheCap.
func TestPathCache_BoundedSize(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "bnd.apfs")
	fs, err := Format(img, 1<<22, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	d := fs.(*driver)
	d.pathCacheCap = 8 // small cap for the test
	// Create 12 files; only 8 cache entries should ever live at once.
	for i := 0; i < 12; i++ {
		name := "/f" + string(rune('a'+i)) + ".txt"
		if err := fs.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		if _, err := fs.Stat(name); err != nil {
			t.Fatalf("Stat %s: %v", name, err)
		}
	}
	if got := len(d.pathCache); got > 8 {
		t.Errorf("cache size %d exceeds cap 8", got)
	}
}

// TestPathCache_StatHitsAreFast establishes a smoke-test that the
// cache makes repeated Stats faster than the first one. We compare
// counts of FS-tree traversals indirectly by checking the cache is
// populated after the first call.
func TestPathCache_RepeatStatsCached(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "rep.apfs")
	fs, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.WriteFile("/x/y/z.txt", []byte("z"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	d := fs.(*driver)
	for i := 0; i < 5; i++ {
		if _, err := fs.Stat("/x/y/z.txt"); err != nil {
			t.Fatalf("Stat iter %d: %v", i, err)
		}
	}
	// After 5 Stats of the same path, cache should hold the entry
	// (size ≥ 1) — the actual count depends on whether intermediate
	// /x and /x/y are also cached as the walker hits them.
	if len(d.pathCache) == 0 {
		t.Error("cache empty after 5 Stats")
	}
	_ = os.Stat
}
