package filesystem_apfs

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// oldCRC32CTable is a verbatim copy of the hand-rolled CRC-32C (Castagnoli,
// reflected polynomial 0x82F63B78) lookup table that create.go used before it
// was replaced by the standard library's hash/crc32. It is kept here purely as
// the golden reference for the parity test below: it locks in that the
// stdlib-backed crc32cUpdate stays bit-for-bit identical to the primitive
// mkapfs (lib/checksum.c) implements, over which APFS directory-record name
// hashes are computed.
var oldCRC32CTable = func() [256]uint32 {
	var t [256]uint32
	const poly = uint32(0x82F63B78) // CRC-32C reflected
	for i := uint32(0); i < 256; i++ {
		c := i
		for k := 0; k < 8; k++ {
			if c&1 != 0 {
				c = (c >> 1) ^ poly
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()

// oldCRC32CUpdate is the former hand-rolled inner loop, verbatim.
func oldCRC32CUpdate(crc uint32, buf []byte) uint32 {
	for _, b := range buf {
		crc = oldCRC32CTable[byte(crc)^b] ^ (crc >> 8)
	}
	return crc
}

// oldDrecNameHash reproduces drecNameHash using the old primitive, so the
// whole APFS name-hash pipeline (case fold + UTF-32LE encoding + 22-bit mask)
// is proven equivalent, not just the raw CRC step.
func oldDrecNameHash(name string) uint32 {
	hash := uint32(0xFFFFFFFF)
	var buf [4]byte
	for _, r := range name {
		if r == 0 {
			break
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		binary.LittleEndian.PutUint32(buf[:], uint32(r))
		hash = oldCRC32CUpdate(hash, buf[:])
	}
	return hash & 0x3FFFFF
}

// TestCRC32CUpdateParity proves the stdlib-backed crc32cUpdate is bit-for-bit
// identical to the removed hand-rolled table+loop over a large sweep of random
// seeds and buffers.
func TestCRC32CUpdateParity(t *testing.T) {
	rng := rand.New(rand.NewSource(0xA9F5))
	for i := 0; i < 100000; i++ {
		seed := rng.Uint32()
		buf := make([]byte, rng.Intn(48))
		rng.Read(buf)
		if got, want := crc32cUpdate(seed, buf), oldCRC32CUpdate(seed, buf); got != want {
			t.Fatalf("crc32cUpdate mismatch seed=%08x buf=%x: got %08x want %08x", seed, buf, got, want)
		}
	}
	// Explicit edge cases: empty buffer must be a no-op; seed 0 and ~0.
	for _, seed := range []uint32{0, 0xFFFFFFFF, 0x12345678} {
		if got, want := crc32cUpdate(seed, nil), oldCRC32CUpdate(seed, nil); got != want {
			t.Fatalf("empty-buffer mismatch seed=%08x: got %08x want %08x", seed, got, want)
		}
	}
}

// TestDrecNameHashParity proves the full directory-record name hash matches the
// old implementation over representative and randomized names, including the
// ASCII case-fold path, non-ASCII runes, the embedded-NUL cutoff, and the empty
// name.
func TestDrecNameHashParity(t *testing.T) {
	fixed := []string{
		"", "a", "A", "z", "Z",
		".", "..", "root", "private-dir",
		"fileA.txt", "filea.txt", // must fold to the same hash
		"MixedCASE.Name", "the quick brown fox jumps",
		"héllo", "café", "日本語", "Ωmega",
		"a\x00b", "trailing\x00", "\x00leading",
		"￿", "emoji-\U0001F600",
	}
	for _, nm := range fixed {
		if got, want := drecNameHash(nm), oldDrecNameHash(nm); got != want {
			t.Fatalf("drecNameHash(%q): got %06x want %06x", nm, got, want)
		}
	}
	// fileA.txt / filea.txt case-insensitivity is load-bearing for the writer.
	if drecNameHash("fileA.txt") != drecNameHash("filea.txt") {
		t.Fatalf("case fold broken: %06x != %06x", drecNameHash("fileA.txt"), drecNameHash("filea.txt"))
	}

	rng := rand.New(rand.NewSource(0x5EED))
	for i := 0; i < 20000; i++ {
		runes := make([]rune, rng.Intn(24))
		for j := range runes {
			runes[j] = rune(rng.Intn(0x2000))
		}
		nm := string(runes)
		if got, want := drecNameHash(nm), oldDrecNameHash(nm); got != want {
			t.Fatalf("drecNameHash(%q): got %06x want %06x", nm, got, want)
		}
	}
}
