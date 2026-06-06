package filesystem_apfs

import (
	"path/filepath"
	"testing"

	filesystem "github.com/go-filesystems/interface"
)

// TestDriver_Label_DelegatesToVolumeName verifies the driver's Label()
// method returns the underlying APFS volume's volname. APFS volume
// rename is transactional / COW and out of scope for the driver — the
// LabelReader capability documents the read-only restriction.
func TestDriver_Label_DelegatesToVolumeName(t *testing.T) {
	const want = "MyAPFSDisk"
	tmp := t.TempDir()
	path := filepath.Join(tmp, "img.dmg")

	fs, err := Format(path, 64*1024*1024, FormatConfig{Label: want})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	defer fs.Close()

	d, ok := fs.(*driver)
	if !ok {
		t.Fatalf("Format returned %T, want *driver", fs)
	}
	if got := d.Label(); got != want {
		t.Errorf("Label() = %q, want %q", got, want)
	}
}

func TestDriver_SatisfiesLabelReader_NotLabeller(t *testing.T) {
	// Compile-time-style probe: the assertion in driver.go already
	// ensures *driver satisfies LabelReader. Here we verify at runtime
	// that the asymmetry holds — *driver implements LabelReader but
	// NOT the full Labeller (no SetLabel).
	var fs filesystem.Filesystem = &driver{}
	if _, ok := fs.(filesystem.LabelReader); !ok {
		t.Error("LabelReader probe failed on *driver")
	}
	if _, ok := fs.(filesystem.Labeller); ok {
		t.Error("Labeller probe unexpectedly succeeded on *driver (read-only by design)")
	}
}

func TestDriver_Label_EmptyVolume(t *testing.T) {
	// A *driver with no volume should return "" rather than panic —
	// matches the read-fallback path in openContainerAsFilesystem.
	d := &driver{}
	if got := d.Label(); got != "" {
		t.Errorf("Label() on volume-less driver = %q, want empty", got)
	}
}
