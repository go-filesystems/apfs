package filesystem_apfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Regression for the audit finding below (fixed: readBlock verifies o_cksum).
//
// AUDIT (opus, 2026-11-22): o_cksum is parsed (obj.go) and never compared. A name
// rewritten inside a filesystem-tree leaf, with the block's Fletcher-64 left as it
// was, is listed as if it were genuine; Apple's kernel and fsck_apfs refuse the
// block ("invalid o_cksum").
func TestAuditOpusObjectChecksumNotVerified(t *testing.T) {
	img := filepath.Join(t.TempDir(), "img")
	fsys, err := Format(img, 64<<20, FormatConfig{})
	if err != nil {
		t.Fatal(err)
	}
	orig := []byte("ORIGINALNAMEXYZ.txt")
	if err := fsys.WriteFile("/"+string(orig), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	n := bytes.Count(raw, orig)
	if n == 0 {
		t.Fatal("name not found in image")
	}
	raw = bytes.ReplaceAll(raw, orig, []byte("FORGEDNAMEXYZAB.txt"))
	if err := os.WriteFile(img, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var ce *ChecksumError
	f2, err := Open(img, -1)
	if err != nil {
		if !errors.As(err, &ce) {
			t.Fatalf("refused on open, but not with a *ChecksumError: %v", err)
		}
		return
	}
	defer f2.Close()
	ents, err := f2.ListDir("/")
	if err != nil {
		if !errors.As(err, &ce) {
			t.Fatalf("refused on list, but not with a *ChecksumError: %v", err)
		}
		return
	}
	for _, e := range ents {
		if e.Name() == "FORGEDNAMEXYZAB.txt" {
			t.Errorf("o_cksum not verified: %d block(s) tampered, ListDir returns %q", n, e.Name())
		}
	}
}
