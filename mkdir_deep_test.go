package filesystem_apfs

import (
	"path/filepath"
	"testing"
)

// TestMkDir_DeepPath_AutoCreatesParents pins down the contract that
// `MkDir` auto-creates every intermediate directory in a
// deeply-nested path.
func TestMkDir_DeepPath_AutoCreatesParents(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "deep.apfs")
	fs, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()
	if err := fs.MkDir("/a/b/c/d", 0o755); err != nil {
		t.Fatalf("MkDir deep: %v", err)
	}
	for _, p := range []string{"/a", "/a/b", "/a/b/c", "/a/b/c/d"} {
		if _, err := fs.Stat(p); err != nil {
			t.Errorf("Stat %s: %v", p, err)
		}
	}
}
