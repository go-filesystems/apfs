package filesystem_apfs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenWithKeys_Unencrypted exercises the OpenWithKeys public entry
// point on an unencrypted container: the first openContainerAsFilesystem
// attempt succeeds and the keys list is ignored.
func TestOpenWithKeys_Unencrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owk.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := FormatContainer(path, 1<<22, "OWK"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	fs, err := OpenWithKeys(path, 0, "unused-key")
	if err != nil {
		t.Fatalf("OpenWithKeys: %v", err)
	}
	if fs == nil {
		t.Fatal("OpenWithKeys returned nil filesystem")
	}
	if closer, ok := fs.(interface{ Close() error }); ok {
		closer.Close()
	}
}

// TestOpenWithKeys_NotAPFS covers the error branch where no codec
// recognises the file. On non-darwin it returns ErrNoHeader directly;
// on darwin it tries the hdiutil fallback, which also fails on bogus
// input.
func TestOpenWithKeys_NotAPFS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notapfs.bin")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := OpenWithKeys(path, 0); err == nil {
		t.Fatal("expected error for non-APFS input")
	}
}
