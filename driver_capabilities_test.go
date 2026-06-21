package filesystem_apfs

// driver_capabilities_test.go — exercises the optional filesystem.* write
// capabilities the driver exposes over the Volume/Container engine:
// Symlinker, HardLinker, Truncater and Grower/Resizer.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// newRWDriver formats a fresh container and returns a writable *driver.
func newRWDriver(t *testing.T) *driver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cap.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create image file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "CAP"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume: %v", err)
	}
	d := &driver{c: c, v: v}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// newRODriver formats a fresh container, populates it with one file, then
// reopens it read-only (O_RDONLY ⇒ c.w == nil). This is the root-safe way
// to obtain a non-writable driver: it relies on the explicit nil write
// capability rather than on a file-permission bit (which uid 0 ignores).
func newRODriver(t *testing.T) *driver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ro.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create image file: %v", err)
	}
	if err := FormatContainer(path, 1<<23, "ROCAP"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}
	// Seed a file via a writable handle, then close it.
	{
		rwc, err := OpenContainerRW(path)
		if err != nil {
			t.Fatalf("OpenContainerRW: %v", err)
		}
		rwv, err := rwc.OpenVolume(0)
		if err != nil {
			rwc.Close()
			t.Fatalf("OpenVolume: %v", err)
		}
		rw := &driver{c: rwc, v: rwv}
		if err := rw.WriteFile("/seed.txt", []byte("seed"), 0o644); err != nil {
			t.Fatalf("seed WriteFile: %v", err)
		}
		_ = rw.Close()
	}
	c, err := OpenContainer(path) // O_RDONLY ⇒ c.w == nil
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		t.Fatalf("OpenVolume(RO): %v", err)
	}
	d := &driver{c: c, v: v}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// TestDriverCapabilitiesReadOnly exercises the ErrReadOnly guard on every
// write capability the driver exposes, using an intrinsically read-only
// container (c.w == nil) so the assertion holds regardless of the process
// uid (the QEMU jobs run as root).
func TestDriverCapabilitiesReadOnly(t *testing.T) {
	d := newRODriver(t)
	if err := d.Symlink("/seed.txt", "/link"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Symlink RO: got %v, want ErrReadOnly", err)
	}
	if err := d.Link("/seed.txt", "/alias"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Link RO: got %v, want ErrReadOnly", err)
	}
	if err := d.Truncate("/seed.txt", 1); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Truncate RO: got %v, want ErrReadOnly", err)
	}
	if err := d.GrowTo(1 << 24); !errors.Is(err, ErrReadOnly) {
		t.Errorf("GrowTo RO: got %v, want ErrReadOnly", err)
	}
	if err := d.Resize(1 << 24); !errors.Is(err, ErrReadOnly) {
		t.Errorf("Resize RO: got %v, want ErrReadOnly", err)
	}
}

// TestDriverCapabilitiesErrorBranches covers the remaining argument-validation
// and lookup-failure branches of the write capabilities that the happy-path
// tests don't reach.
func TestDriverCapabilitiesErrorBranches(t *testing.T) {
	d := newRWDriver(t)
	if err := d.WriteFile("/src.txt", []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Symlink: empty link name.
	if err := d.Symlink("/src.txt", "/"); err == nil {
		t.Error("Symlink empty name: want error")
	}
	// Symlink: parent directory does not exist.
	if err := d.Symlink("/src.txt", "/nope/link"); err == nil {
		t.Error("Symlink missing parent: want error")
	}

	// Link: empty target name.
	if err := d.Link("/src.txt", "/"); err == nil {
		t.Error("Link empty name: want error")
	}
	// Link: source does not exist.
	if err := d.Link("/missing", "/alias"); err == nil {
		t.Error("Link missing source: want error")
	}
	// Link: parent directory does not exist.
	if err := d.Link("/src.txt", "/nope/alias"); err == nil {
		t.Error("Link missing parent: want error")
	}

	// Truncate: negative size.
	if err := d.Truncate("/src.txt", -1); err == nil {
		t.Error("Truncate negative size: want error")
	}
	// Truncate: path does not exist.
	if err := d.Truncate("/missing", 0); err == nil {
		t.Error("Truncate missing path: want error")
	}
}

func TestDriverSymlinkCapability(t *testing.T) {
	var _ filesystem.Symlinker = (*driver)(nil)
	d := newRWDriver(t)
	if err := d.WriteFile("/target.txt", []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := d.Symlink("/target.txt", "/link"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	got, err := d.ReadLink("/link")
	if err != nil {
		t.Fatalf("ReadLink: %v", err)
	}
	if strings.TrimRight(got, "\x00") != "/target.txt" {
		t.Fatalf("ReadLink = %q, want /target.txt", got)
	}
	// Creating over an existing name must fail.
	if err := d.Symlink("/x", "/link"); err == nil {
		t.Fatal("Symlink over existing name: expected error")
	}
}

func TestDriverHardLinkCapability(t *testing.T) {
	var _ filesystem.HardLinker = (*driver)(nil)
	d := newRWDriver(t)
	if err := d.WriteFile("/orig.bin", []byte("shared-bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := d.Link("/orig.bin", "/alias.bin"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	got, err := d.ReadFile("/alias.bin")
	if err != nil {
		t.Fatalf("ReadFile(alias): %v", err)
	}
	if string(got) != "shared-bytes" {
		t.Fatalf("hardlink content = %q, want shared-bytes", got)
	}
	// Linking a directory must be rejected.
	if err := d.MkDir("/d", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := d.Link("/d", "/d2"); err == nil {
		t.Fatal("Link of directory: expected error")
	}
}

func TestDriverTruncateCapability(t *testing.T) {
	var _ filesystem.Truncater = (*driver)(nil)
	d := newRWDriver(t)
	body := make([]byte, 100)
	for i := range body {
		body[i] = byte('A' + i%26)
	}
	if err := d.WriteFile("/t.bin", body, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Shrink.
	if err := d.Truncate("/t.bin", 10); err != nil {
		t.Fatalf("Truncate shrink: %v", err)
	}
	got, err := d.ReadFile("/t.bin")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 10 || string(got) != string(body[:10]) {
		t.Fatalf("after shrink: len=%d content=%q", len(got), got)
	}
	// Grow with implicit zero-fill.
	if err := d.Truncate("/t.bin", 40); err != nil {
		t.Fatalf("Truncate grow: %v", err)
	}
	got, err = d.ReadFile("/t.bin")
	if err != nil {
		t.Fatalf("ReadFile after grow: %v", err)
	}
	if len(got) != 40 {
		t.Fatalf("after grow: len=%d, want 40", len(got))
	}
	for i := 10; i < 40; i++ {
		if got[i] != 0 {
			t.Fatalf("grown region not zero-filled at %d: %d", i, got[i])
		}
	}
	// Truncating a directory must be rejected.
	if err := d.MkDir("/dir", 0o755); err != nil {
		t.Fatalf("MkDir: %v", err)
	}
	if err := d.Truncate("/dir", 0); err == nil {
		t.Fatal("Truncate of directory: expected error")
	}
}

func TestDriverGrowResizeCapability(t *testing.T) {
	var (
		_ filesystem.Grower  = (*driver)(nil)
		_ filesystem.Resizer = (*driver)(nil)
	)
	d := newRWDriver(t)
	if err := d.WriteFile("/keep.txt", []byte("survives"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := d.GrowTo(1 << 24); err != nil { // 8 MiB → 16 MiB
		t.Fatalf("GrowTo: %v", err)
	}
	// Data survives the grow.
	got, err := d.ReadFile("/keep.txt")
	if err != nil || string(got) != "survives" {
		t.Fatalf("post-grow ReadFile = %q, %v", got, err)
	}
	// Resize is the uniform entry point; growing further must succeed.
	if err := d.Resize(1 << 25); err != nil { // → 32 MiB
		t.Fatalf("Resize grow: %v", err)
	}
}
