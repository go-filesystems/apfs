//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	apfsfde "github.com/go-fde/apfs"
)

// TestProbe_TwoAppleReferences byte-diffs two Apple-encrypted reference
// DMGs to identify which keybag-block bytes are STRUCTURAL constants
// (same across both refs — must be replicated by our writer) vs which
// are PER-INSTANCE (different per ref — UUIDs, cksums, salts, paddrs,
// wrapped keys). The constant bytes that we don't yet emit are the
// missing piece between our keybag and the one fsck_apfs accepts.
//
// ref.dmg  — passphrase = "apfsfde-probe-password" (16 MiB)
// ref2.dmg — passphrase = "another-pass-456"      (32 MiB)
func TestProbe_TwoAppleReferences(t *testing.T) {
	type refDMG struct {
		path       string
		passphrase string
	}
	refs := []refDMG{
		{"/tmp/appleref/ref.dmg", "apfsfde-probe-password"},
		{"/tmp/appleref/ref2.dmg", "another-pass-456"},
	}
	for _, r := range refs {
		if _, err := os.Stat(r.path); err != nil {
			t.Skipf("needs %s: %v", r.path, err)
		}
	}

	const apfsPartByteOff = 20480 // LBA 40
	const blockSize = 4096

	type refDecoded struct {
		path             string
		containerUUID    [16]byte
		volumeUUID       [16]byte
		containerKBPaddr uint64
		volumeKBPaddr    uint64
		containerKBPlain []byte
		volumeKBPlain    []byte // VEK-encrypted; we leave it as-is for byte-diff
		volumeKBCipher   []byte
		vek              []byte
	}
	decoded := make([]refDecoded, len(refs))

	for i, r := range refs {
		f, err := os.Open(r.path)
		if err != nil {
			t.Fatalf("open %s: %v", r.path, err)
		}
		defer f.Close()

		nx := make([]byte, blockSize)
		if _, err := f.ReadAt(nx, apfsPartByteOff); err != nil {
			t.Fatal(err)
		}
		copy(decoded[i].containerUUID[:], nx[72:88])
		decoded[i].containerKBPaddr = binary.LittleEndian.Uint64(nx[1296:1304])

		ckCipher := make([]byte, blockSize)
		f.ReadAt(ckCipher, apfsPartByteOff+int64(decoded[i].containerKBPaddr)*blockSize)
		ckPlain, err := apfsfde.DecryptContainerKeybag(ckCipher, decoded[i].containerUUID, decoded[i].containerKBPaddr)
		if err != nil {
			t.Fatalf("decrypt ref%d container kb: %v", i, err)
		}
		decoded[i].containerKBPlain = ckPlain

		// Walk the entries to extract volume UUID, volume kb paddr, and VEKBLOB.
		nkeys := int(binary.LittleEndian.Uint16(ckPlain[34:36]))
		off := 48
		var vekBlobBytes []byte
		for j := 0; j < nkeys; j++ {
			var u [16]byte
			copy(u[:], ckPlain[off:off+16])
			tag := binary.LittleEndian.Uint16(ckPlain[off+16 : off+18])
			keylen := int(binary.LittleEndian.Uint16(ckPlain[off+18 : off+20]))
			ds := off + 24
			de := ds + keylen
			switch tag {
			case 3:
				decoded[i].volumeUUID = u
				decoded[i].volumeKBPaddr = binary.LittleEndian.Uint64(ckPlain[ds : ds+8])
			case 2:
				vekBlobBytes = append([]byte{}, ckPlain[ds:de]...)
			}
			next := de
			if rem := next % 16; rem != 0 {
				next += 16 - rem
			}
			off = next
		}

		// Volume keybag.
		vkCipher := make([]byte, blockSize)
		f.ReadAt(vkCipher, apfsPartByteOff+int64(decoded[i].volumeKBPaddr)*blockSize)
		decoded[i].volumeKBCipher = vkCipher
		vkPlain, err := apfsfde.DecryptVolumeKeybag(vkCipher, decoded[i].volumeUUID, decoded[i].volumeKBPaddr)
		if err != nil {
			t.Fatalf("decrypt ref%d volume kb: %v", i, err)
		}
		decoded[i].volumeKBPlain = vkPlain

		// Recover VEK to verify chain works.
		kekBlobBytes := walkVolumeKB(t, vkPlain)
		decoded[i].vek = unlockVEKFromBlobs(t, []byte(r.passphrase), kekBlobBytes, vekBlobBytes)
		t.Logf("ref%d: containerUUID=%x volumeUUID=%x containerKB@%d volumeKB@%d VEK_len=%d",
			i, decoded[i].containerUUID, decoded[i].volumeUUID,
			decoded[i].containerKBPaddr, decoded[i].volumeKBPaddr, len(decoded[i].vek))
	}

	// ── Container keybag byte-diff ────────────────────────────────────
	t.Log("=== CONTAINER KEYBAG byte-diff (ref0 vs ref1) ===")
	dumpKeybagDiff(t, decoded[0].containerKBPlain, decoded[1].containerKBPlain, "container")
	t.Log("=== VOLUME KEYBAG byte-diff (ref0 vs ref1) ===")
	dumpKeybagDiff(t, decoded[0].volumeKBPlain, decoded[1].volumeKBPlain, "volume")

	// Dump ref0's container keybag bytes around offset 0xF0 to see the
	// "extra" data Apple writes past the entry[1] data.
	t.Log("=== ref0 container keybag bytes +0x060..+0x110 (entry[1] full) ===")
	t.Logf("\n%s", hex.Dump(decoded[0].containerKBPlain[0x60:0x110]))
	t.Log("=== ref1 container keybag bytes +0x060..+0x110 (entry[1] full) ===")
	t.Logf("\n%s", hex.Dump(decoded[1].containerKBPlain[0x60:0x110]))
}

// dumpKeybagDiff prints the bytes that DIFFER between the two refs
// (per-instance fields) and the bytes that are STRUCTURAL CONSTANTS.
// We're particularly interested in the latter — anything constant
// between two independently-encrypted Apple references is a fixed
// value our writer must reproduce.
func dumpKeybagDiff(t *testing.T, a, b []byte, label string) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("%s len mismatch: %d vs %d", label, len(a), len(b))
	}
	// Print summary: byte-by-byte diff status, grouped into runs.
	type run struct {
		off    int
		length int
		same   bool
	}
	runs := []run{}
	cur := run{off: 0, length: 1, same: a[0] == b[0]}
	for i := 1; i < len(a); i++ {
		s := a[i] == b[i]
		if s == cur.same {
			cur.length++
		} else {
			runs = append(runs, cur)
			cur = run{off: i, length: 1, same: s}
		}
	}
	runs = append(runs, cur)

	// Trim trailing all-zero/all-same run if it goes to end of block (boring).
	totalDiff := 0
	for _, r := range runs {
		if !r.same {
			totalDiff += r.length
		}
	}
	t.Logf("%s: total bytes differing = %d / %d", label, totalDiff, len(a))

	// Print only the first 0x200 bytes of structural detail — the
	// rest is mostly all-zero padding past the entry area.
	for _, r := range runs {
		if r.off >= 0x200 {
			break
		}
		end := r.off + r.length
		if end > 0x200 {
			end = 0x200
		}
		status := "DIFF"
		if r.same {
			status = "SAME"
		}
		// For SAME runs we want the byte values (they're CONSTANTS).
		// For DIFF runs we just note the range.
		if r.same {
			// Skip showing all-zero same runs (boring).
			allZero := true
			for i := r.off; i < end; i++ {
				if a[i] != 0 {
					allZero = false
					break
				}
			}
			if allZero && r.length >= 4 {
				t.Logf("%s [+0x%03x..+0x%03x] %s zeros (%d bytes)", label, r.off, end-1, status, r.length)
				continue
			}
			t.Logf("%s [+0x%03x..+0x%03x] %s constant: %s", label, r.off, end-1, status, hexShort(a[r.off:end]))
		} else {
			t.Logf("%s [+0x%03x..+0x%03x] %s (%d bytes; ref0=%s ref1=%s)",
				label, r.off, end-1, status, end-r.off,
				hexShort(a[r.off:end]), hexShort(b[r.off:end]))
		}
	}
}

func hexShort(b []byte) string {
	if len(b) <= 16 {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:8]) + "..." + hex.EncodeToString(b[len(b)-8:])
}

// (Suppress unused-import warnings.)
var (
	_ = fmt.Sprintf
	_ = strings.Builder{}
)
