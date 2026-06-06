package filesystem_apfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestMountPathToReal pins the path-join + "/"-as-root contract.
func TestMountPathToReal(t *testing.T) {
	cases := []struct {
		mountpoint, logical, want string
	}{
		{"/mnt/img", "", "/mnt/img"},
		{"/mnt/img", "/", "/mnt/img"},
		{"/mnt/img", "/foo", "/mnt/img/foo"},
		{"/mnt/img", "/a/b/c", "/mnt/img/a/b/c"},
		// No leading slash → still joins.
		{"/mnt/img", "rel/path", "/mnt/img/rel/path"},
	}
	for _, tc := range cases {
		if got := mountPathToReal(tc.mountpoint, tc.logical); got != tc.want {
			t.Errorf("mountPathToReal(%q, %q) = %q, want %q", tc.mountpoint, tc.logical, got, tc.want)
		}
	}
}

// TestMountMode_RoundTrip exercises every package-private
// mountMode* helper against a temp directory standing in for a
// hdiutil-attached mountpoint. These helpers are the OS-passthrough
// path the driver takes when its `mountpoint` field is non-empty.
func TestMountMode_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	// MkDir → ListDir
	if err := mountModeMkDir(dir, "/sub", 0o755); err != nil {
		t.Fatalf("mountModeMkDir: %v", err)
	}
	// WriteFile → ReadFile
	want := []byte("hello mountpoint")
	if err := mountModeWriteFile(dir, "/sub/file.txt", want, 0o644); err != nil {
		t.Fatalf("mountModeWriteFile: %v", err)
	}
	got, err := mountModeReadFile(dir, "/sub/file.txt")
	if err != nil {
		t.Fatalf("mountModeReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read mismatch: got %q, want %q", got, want)
	}
	// ListDir
	entries, err := mountModeListDir(dir, "/sub")
	if err != nil {
		t.Fatalf("mountModeListDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		t.Fatalf("ListDir: got %+v, want [file.txt]", entries)
	}
	// Stat
	st, err := mountModeStat(dir, "/sub/file.txt")
	if err != nil {
		t.Fatalf("mountModeStat: %v", err)
	}
	if st.Size() != uint64(len(want)) {
		t.Errorf("Stat size: got %d, want %d", st.Size(), len(want))
	}
	// Symlink + ReadLink
	if err := os.Symlink("file.txt", filepath.Join(dir, "sub", "link")); err != nil {
		t.Fatalf("symlink seed: %v", err)
	}
	target, err := mountModeReadLink(dir, "/sub/link")
	if err != nil {
		t.Fatalf("mountModeReadLink: %v", err)
	}
	if target != "file.txt" {
		t.Errorf("ReadLink: got %q, want %q", target, "file.txt")
	}
	// Rename
	if err := mountModeRename(dir, "/sub/file.txt", "/sub/renamed.txt"); err != nil {
		t.Fatalf("mountModeRename: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "renamed.txt")); err != nil {
		t.Errorf("renamed file not found: %v", err)
	}
	// DeleteFile
	if err := mountModeDeleteFile(dir, "/sub/renamed.txt"); err != nil {
		t.Fatalf("mountModeDeleteFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "renamed.txt")); !os.IsNotExist(err) {
		t.Errorf("file still exists: %v", err)
	}
	// DeleteDir
	_ = os.Remove(filepath.Join(dir, "sub", "link")) // clear residual
	if err := mountModeDeleteDir(dir, "/sub"); err != nil {
		t.Fatalf("mountModeDeleteDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); !os.IsNotExist(err) {
		t.Errorf("dir still exists: %v", err)
	}
}

// TestMountMode_ReadFile_OnRootIsDirectory covers the root-is-a-
// directory error path in mountModeReadFile.
func TestMountMode_ReadFile_OnRootIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := mountModeReadFile(dir, "/"); err == nil {
		t.Fatal("expected error reading root as file")
	}
	if _, err := mountModeReadFile(dir, ""); err == nil {
		t.Fatal("expected error reading empty path as file")
	}
}

// TestMountMode_ErrorPaths drives each helper at a missing path
// to cover the os-error forwarding branches.
func TestMountMode_ErrorPaths(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		fn   func() error
	}{
		{"ReadFile-missing", func() error {
			_, err := mountModeReadFile(dir, "/missing.txt")
			return err
		}},
		{"ListDir-missing", func() error {
			_, err := mountModeListDir(dir, "/missing")
			return err
		}},
		{"Stat-missing", func() error {
			_, err := mountModeStat(dir, "/missing")
			return err
		}},
		{"ReadLink-missing", func() error {
			_, err := mountModeReadLink(dir, "/missing")
			return err
		}},
		{"DeleteFile-missing", func() error {
			return mountModeDeleteFile(dir, "/missing.txt")
		}},
		// DeleteDir on a missing path uses os.RemoveAll which is
		// idempotent and doesn't return an error — skip that case.
		{"Rename-missing", func() error {
			return mountModeRename(dir, "/missing.txt", "/somewhere.txt")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.fn(); err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
		})
	}
}
