//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	apfsfde "github.com/go-fde/apfs"
	"golang.org/x/crypto/xts"
)

// TestProbe_FsckBisectKeybagFields formats an encrypted GPT-wrapped
// container, then for each named scenario applies a SPECIFIC byte
// mutation to the on-disk container keybag (re-encrypting at-rest
// after the mutation), runs `fsck_apfs -nld`, and captures the exact
// error message. The goal is to map fsck's error vocabulary so we
// can tell whether "Bad message" is fsck's catch-all or whether
// different mutations produce different errors.
//
// If different mutations all produce IDENTICAL "Bad message" errors,
// the check that's failing is fsck's generic post-decrypt validator
// (cksum, version, type) and our keybag must be passing those —
// confirming the gap is in a check after that we can't observe.
//
// If different mutations produce DIFFERENT errors, fsck's error
// reporting is granular enough to bisect — and the unique ones
// might point at the actual gating check.
func TestProbe_FsckBisectKeybagFields(t *testing.T) {
	requireTool(t, "hdiutil")
	requireTool(t, "fsck_apfs")

	type mutation struct {
		name string
		// fn applies the mutation in-place to the decrypted keybag.
		// After fn runs, the test re-seals (Fletcher-64 over [+8..end]),
		// re-encrypts with the container UUID, and writes back.
		// If skipReseal is true, the cksum is left as fn produced it
		// (useful for testing fsck's response to a corrupt cksum).
		fn         func(plain []byte)
		skipReseal bool
	}
	mutations := []mutation{
		{"baseline (no mutation)", func(p []byte) {}, false},
		{"obj_phys.type = 0x00000000 (zero)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[24:28], 0)
		}, false},
		{"obj_phys.type = 0xFFFFFFFF", func(p []byte) {
			binary.LittleEndian.PutUint32(p[24:28], 0xFFFFFFFF)
		}, false},
		{"obj_phys.type = OBJECT_TYPE_FS (0x0D — bogus for keybag)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[24:28], 0x0D)
		}, false},
		{"obj_phys.subtype = 0xDEADBEEF (was 0)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[28:32], 0xDEADBEEF)
		}, false},
		{"kl_version = 1 (was 2)", func(p []byte) {
			binary.LittleEndian.PutUint16(p[32:34], 1)
		}, false},
		{"kl_version = 99 (was 2)", func(p []byte) {
			binary.LittleEndian.PutUint16(p[32:34], 99)
		}, false},
		{"kl_nkeys = 0 (was 2)", func(p []byte) {
			binary.LittleEndian.PutUint16(p[34:36], 0)
		}, false},
		{"kl_nkeys = 99 (was 2)", func(p []byte) {
			binary.LittleEndian.PutUint16(p[34:36], 99)
		}, false},
		{"kl_nbytes = 0 (was 224)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[36:40], 0)
		}, false},
		{"kl_nbytes = 208 (entries-only, off by 16)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[36:40], 208)
		}, false},
		{"kl_nbytes = 4000 (way too big)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[36:40], 4000)
		}, false},
		{"corrupt cksum (skip reseal)", func(p []byte) {
			binary.LittleEndian.PutUint64(p[0:8], 0xDEADBEEFCAFEBABE)
		}, true},
		{"obj_phys.oid = paddr (=91)", func(p []byte) {
			binary.LittleEndian.PutUint64(p[8:16], 91)
		}, false},
		{"obj_phys.xid = 0", func(p []byte) {
			binary.LittleEndian.PutUint64(p[16:24], 0)
		}, false},
		{"obj_phys.xid = 100 (high)", func(p []byte) {
			binary.LittleEndian.PutUint64(p[16:24], 100)
		}, false},
		{"entry[0].tag = 99 (was 3)", func(p []byte) {
			binary.LittleEndian.PutUint16(p[64:66], 99)
		}, false},
		{"entry[1].tag = 99 (was 2)", func(p []byte) {
			binary.LittleEndian.PutUint16(p[112:114], 99)
		}, false},
		{"obj_phys.type = type | EPHEMERAL (0x80000000)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[24:28], 0x6b657973|0x80000000)
		}, false},
		{"obj_phys.type = type | PHYSICAL (0x40000000)", func(p []byte) {
			binary.LittleEndian.PutUint32(p[24:28], 0x6b657973|0x40000000)
		}, false},
	}

	results := make(map[string]string)
	for i, m := range mutations {
		dir := t.TempDir()
		path := filepath.Join(dir, fmt.Sprintf("bisect-%02d.apfs", i))
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := FormatContainerEncryptedGPT(path, 1<<25, "Bisect", []byte("p")); err != nil {
			t.Fatalf("[%s] FormatContainerEncryptedGPT: %v", m.name, err)
		}

		// Apply mutation to the on-disk container keybag.
		if err := applyKeybagMutation(path, m.fn, m.skipReseal); err != nil {
			t.Fatalf("[%s] applyKeybagMutation: %v", m.name, err)
		}

		// Run fsck and capture its error.
		errMsg := runFsckAndCaptureError(t, path)
		results[m.name] = errMsg
		t.Logf("[%-58s] → %s", m.name, errMsg)
	}

	// Group mutations by their fsck error message — different errors
	// = fsck distinguishes them = we have a granular signal.
	groups := make(map[string][]string)
	for name, err := range results {
		groups[err] = append(groups[err], name)
	}
	t.Logf("\n=== Error-message groups (%d distinct) ===", len(groups))
	for err, names := range groups {
		t.Logf("error: %q (matches %d mutations)", err, len(names))
		for _, n := range names {
			t.Logf("    - %s", n)
		}
	}
}

// applyKeybagMutation reads the on-disk encrypted container keybag,
// decrypts it, applies fn, optionally re-seals the cksum, re-encrypts,
// and writes back.
func applyKeybagMutation(path string, fn func([]byte), skipReseal bool) error {
	const apfsPartByteOff = int64(1 << 20) // GPT prefix = 1 MiB
	const blockSize = 4096

	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read NX SB at byte 1 MiB (start of Apple_APFS partition in our GPT).
	nxSB := make([]byte, blockSize)
	if _, err := f.ReadAt(nxSB, apfsPartByteOff); err != nil {
		return fmt.Errorf("read NX SB: %w", err)
	}
	var containerUUID [16]byte
	copy(containerUUID[:], nxSB[72:88])
	keybagPaddr := binary.LittleEndian.Uint64(nxSB[1296:1304])

	// Read encrypted keybag.
	cipher := make([]byte, blockSize)
	cipherOff := apfsPartByteOff + int64(keybagPaddr)*blockSize
	if _, err := f.ReadAt(cipher, cipherOff); err != nil {
		return fmt.Errorf("read encrypted kb: %w", err)
	}

	plain, err := apfsfde.DecryptContainerKeybag(cipher, containerUUID, keybagPaddr)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	// Apply mutation.
	fn(plain)

	// Re-seal Fletcher-64 unless skipped.
	if !skipReseal {
		for i := 0; i < 8; i++ {
			plain[i] = 0
		}
		cksum := fletcher64(plain[8:])
		binary.LittleEndian.PutUint64(plain[0:8], cksum)
	}

	// Re-encrypt at rest.
	newCipher, err := encryptKeybagInPlace(plain, containerUUID, keybagPaddr)
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}
	if _, err := f.WriteAt(newCipher, cipherOff); err != nil {
		return fmt.Errorf("write back: %w", err)
	}
	return nil
}

// encryptKeybagInPlace mirrors apfsfde.EncryptContainerKeybag but
// inlined here to avoid threading a single-block helper through the
// public API. AES-XTS-128 with key = uuid||uuid, 512-byte sectors,
// tweak = paddr*8 + sector_index_within_block.
func encryptKeybagInPlace(plain []byte, uuid [16]byte, paddr uint64) ([]byte, error) {
	if len(plain)%4096 != 0 {
		return nil, fmt.Errorf("plain length %d not multiple of 4096", len(plain))
	}
	key := append(append([]byte{}, uuid[:]...), uuid[:]...)
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	const sectorSize = 512
	for blockOff := 0; blockOff < len(plain); blockOff += 4096 {
		base := paddr + uint64(blockOff/4096)
		for s := 0; s < 4096/sectorSize; s++ {
			off := blockOff + s*sectorSize
			c.Encrypt(out[off:off+sectorSize], plain[off:off+sectorSize], base*8+uint64(s))
		}
	}
	return out, nil
}

// runFsckAndCaptureError attaches the image, runs fsck_apfs, parses
// the most-specific error message out of the output, then detaches.
func runFsckAndCaptureError(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		"-stdinpass",
		path,
	).CombinedOutput()
	cmd := strings.NewReader("p\n")
	_ = cmd
	if err != nil {
		return fmt.Sprintf("hdiutil-attach-failed: %v", err)
	}
	dev := parseHdiutilAttachContainer(t, out)
	defer exec.Command("hdiutil", "detach", "-force", dev).Run()

	fsckCmd := exec.Command("fsck_apfs", "-nld", "-E", "-", dev)
	fsckOut, _ := fsckCmd.CombinedOutput()
	return summarizeFsckError(string(fsckOut))
}

// summarizeFsckError extracts the meaningful error line(s) from
// fsck_apfs output, stripping the boilerplate.
func summarizeFsckError(out string) string {
	// Look for the first "error:" line.
	errRE := regexp.MustCompile(`(?m)^\s*error: .*$`)
	if m := errRE.FindString(out); m != "" {
		return strings.TrimSpace(m)
	}
	// Look for "Encryption key structures are invalid" or similar.
	failRE := regexp.MustCompile(`(?m)^\s*(\S.* (invalid|failed|verified completely)\..*)$`)
	if m := failRE.FindString(out); m != "" {
		return strings.TrimSpace(m)
	}
	// No error → fsck passed.
	if strings.Contains(out, "could not be verified completely") {
		return "INCOMPLETE-VERIFICATION"
	}
	if strings.Contains(out, "appears to be OK") {
		return "PASS"
	}
	return "UNKNOWN"
}
