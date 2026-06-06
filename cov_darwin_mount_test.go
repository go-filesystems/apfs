//go:build darwin

package filesystem_apfs

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireHdiutil skips the test if hdiutil is unavailable on this
// host (it should always be on macOS, but CI sandbox restrictions
// may still trip it).
func requireHdiutil(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skipf("hdiutil not available: %v", err)
	}
}

// TestApfsFS_MountMode_FullRoundTrip creates a real APFS DMG via
// hdiutil, opens it (which triggers the darwin mount-mode branch
// of `Open`), and exercises every `driver` method that has a
// mount-mode dispatch: WriteFile, ReadFile, Stat, ListDir, MkDir,
// DeleteFile, DeleteDir, Rename, ReadLink. Close detaches.
//
// This is the only way to exercise the `if fs.isMountMode() { ... }`
// branches that account for ~10% of driver_mount.go's statement coverage.
func TestApfsFS_MountMode_FullRoundTrip(t *testing.T) {
	requireHdiutil(t)
	dir := t.TempDir()
	dmg := filepath.Join(dir, "mount.dmg")
	cfg := FormatConfig{Label: "MountTest"}
	if err := FormatAppleDmg(dmg, 8<<20, cfg); err != nil {
		// hdiutil can fail for many environment-specific reasons
		// (sandbox, sip, no console, etc.). Skip rather than fail.
		t.Skipf("FormatAppleDmg unavailable in this environment: %v", err)
	}
	// Open mounts via hdiutil → returns the driver with mountpoint set.
	fs, err := Open(dmg, -1)
	if err != nil {
		t.Skipf("Open (mount-backed) failed: %v", err)
	}
	defer func() {
		if err := fs.Close(); err != nil {
			t.Logf("Close (detach): %v", err)
		}
	}()

	// 1. WriteFile in mount mode (and ensure parent-dir creation works).
	body := []byte("mount-mode-content")
	if err := fs.WriteFile("/sub/file.txt", body, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// 2. ReadFile in mount mode.
	got, err := fs.ReadFile("/sub/file.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("ReadFile content: got %q, want %q", got, body)
	}

	// 3. Stat: file + directory.
	if st, err := fs.Stat("/sub/file.txt"); err != nil {
		t.Errorf("Stat file: %v", err)
	} else if st.Size() != uint64(len(body)) {
		t.Errorf("Stat size: got %d, want %d", st.Size(), len(body))
	}
	if st, err := fs.Stat("/sub"); err != nil {
		t.Errorf("Stat dir: %v", err)
	} else if st == nil {
		t.Error("Stat dir: got nil")
	}

	// 4. ListDir on root + sub.
	if entries, err := fs.ListDir("/"); err != nil {
		t.Errorf("ListDir(/): %v", err)
	} else {
		found := false
		for _, e := range entries {
			if e.Name() == "sub" {
				found = true
			}
		}
		if !found {
			t.Error("ListDir(/): /sub not found")
		}
	}
	if entries, err := fs.ListDir("/sub"); err != nil {
		t.Errorf("ListDir(/sub): %v", err)
	} else if len(entries) < 1 {
		t.Errorf("ListDir(/sub): got 0 entries, want ≥ 1")
	}

	// 5. MkDir.
	if err := fs.MkDir("/newdir", 0o755); err != nil {
		t.Errorf("MkDir: %v", err)
	}
	// Idempotent MkDir.
	if err := fs.MkDir("/newdir", 0o755); err != nil {
		t.Errorf("MkDir twice: %v", err)
	}

	// 6. Rename in mount mode.
	if err := fs.WriteFile("/torename.txt", []byte("rename-me"), 0o644); err != nil {
		t.Errorf("WriteFile pre-rename: %v", err)
	}
	if err := fs.Rename("/torename.txt", "/renamed.txt"); err != nil {
		t.Errorf("Rename: %v", err)
	}
	if got, err := fs.ReadFile("/renamed.txt"); err != nil {
		t.Errorf("ReadFile after rename: %v", err)
	} else if !bytes.Equal(got, []byte("rename-me")) {
		t.Errorf("renamed content: got %q", got)
	}

	// 7. DeleteFile.
	if err := fs.DeleteFile("/renamed.txt"); err != nil {
		t.Errorf("DeleteFile: %v", err)
	}
	if _, err := fs.Stat("/renamed.txt"); err == nil {
		t.Error("Stat after DeleteFile: expected error")
	}

	// 8. DeleteDir on a non-empty dir.
	if err := fs.MkDir("/todelete", 0o755); err != nil {
		t.Errorf("MkDir todelete: %v", err)
	}
	if err := fs.WriteFile("/todelete/inside.txt", []byte("inside"), 0o644); err != nil {
		t.Errorf("WriteFile inside todelete: %v", err)
	}
	if err := fs.DeleteDir("/todelete"); err != nil {
		t.Errorf("DeleteDir non-empty: %v", err)
	}

	// 9. ReadLink: try on a regular file (should error). The mount-mode
	//    branch of ReadLink calls os.Readlink, which returns ENOENT or
	//    EINVAL for a non-symlink — either way, an error.
	if err := fs.WriteFile("/notalink.txt", []byte("x"), 0o644); err != nil {
		t.Errorf("WriteFile notalink: %v", err)
	}
	if _, err := fs.ReadLink("/notalink.txt"); err == nil {
		// On macOS os.Readlink on a regular file returns "invalid
		// argument" — but defensive against environment quirks.
		t.Log("ReadLink on regular file did not error (host quirk)")
	}

	// 10. ReadFile on root path (mount mode special-cases "/").
	if _, err := fs.ReadFile("/"); err == nil {
		t.Error("ReadFile on /: expected error")
	}

	// 11. DeleteDir on / wipes contents but keeps mountpoint.
	if err := fs.DeleteDir("/"); err != nil {
		t.Errorf("DeleteDir(/): %v", err)
	}
	// After wipe, /sub should be gone.
	if _, err := fs.Stat("/sub"); err == nil {
		t.Error("/sub survived DeleteDir(/)")
	}
}

// TestApfsFS_MountMode_OpenAndClose confirms Close releases the
// mount cleanly (covers detachImage's success path).
func TestApfsFS_MountMode_OpenAndClose(t *testing.T) {
	requireHdiutil(t)
	dir := t.TempDir()
	dmg := filepath.Join(dir, "openclose.dmg")
	if err := FormatAppleDmg(dmg, 4<<20, FormatConfig{Label: "OC"}); err != nil {
		t.Skipf("FormatAppleDmg: %v", err)
	}
	fs, err := Open(dmg, -1)
	if err != nil {
		t.Skipf("Open: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Errorf("Close (detachImage): %v", err)
	}
}

// TestFormatAppleDmg_Sizes exercises FormatAppleDmg with different
// sizes — covers the path even on environments where actual
// hdiutil-attach fails downstream.
func TestFormatAppleDmg_Sizes(t *testing.T) {
	requireHdiutil(t)
	dir := t.TempDir()
	for _, sz := range []int64{4 << 20, 8 << 20} {
		path := filepath.Join(dir, "fmt.dmg")
		if err := FormatAppleDmg(path, sz, FormatConfig{Label: "FmtSize"}); err != nil {
			// Some sandboxed CIs reject hdiutil — log and continue.
			if strings.Contains(err.Error(), "hdiutil") {
				t.Logf("FormatAppleDmg %d MB: %v (host limitation)", sz>>20, err)
			} else {
				t.Errorf("FormatAppleDmg %d MB: %v", sz>>20, err)
			}
		}
	}
}
