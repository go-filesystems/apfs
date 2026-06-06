package filesystem_apfs

// gpt_wrap.go writes a GPT (GUID Partition Table) wrapper around a raw
// APFS container produced by FormatContainer / FormatContainerEncrypted.
// macOS's apfs.kext consults the partition type GUID to decide whether
// to treat a block range as an APFS physical store. Without the
// Apple_APFS GUID (7C3457EF-…) the kext synthesises an empty container
// scheme device with no volume slices — see go-diskimages/diskimage/
// create.go for the same observation in the unencrypted path.
//
// The layout this writer produces matches what `hdiutil create -fs
// APFS -layout GPTSPUD` puts on disk:
//
//	LBA 0           protective MBR
//	LBA 1           primary GPT header
//	LBA 2..33       primary partition entry array (32 sectors = 16 KiB)
//	LBA 34..2047    pad (typically zero)
//	LBA 2048..N-34  Apple_APFS partition (the APFS container bytes)
//	LBA N-33..N-1   backup partition entry array
//	LBA N-1         backup GPT header (Apple convention; spec allows N)
//
// totalLBA is the file size in 512-byte sectors. apfsSize is the
// number of bytes occupied by the APFS container (caller writes those
// bytes at byte offset 1 MiB before invoking this function).

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
)

const (
	gptHeaderSize  = 92
	gptEntrySize   = 128
	gptMaxEntries  = 128
	gptEntriesLBAs = int64(gptMaxEntries) * gptEntrySize / gptSectorSize // 32
	gptPartFirstLBA = int64(2048) // partition starts at byte offset 1 MiB
)


// appleAPFSPartTypeGUID is the GPT partition type GUID for Apple_APFS,
// already defined in gpt.go and reused here.

// writeAppleAPFSGPT lays a GPT wrapper around an existing file at path,
// declaring a single Apple_APFS partition that spans LBA 2048 through
// the last usable sector. The file's content from byte 1 MiB onward is
// expected to already hold the APFS container; this function only
// touches the boot/header sectors and the GPT entry arrays.
func writeAppleAPFSGPT(path string, totalSize int64) error {
	if totalSize%gptSectorSize != 0 {
		return fmt.Errorf("apfs: GPT wrap: totalSize %d not a multiple of %d", totalSize, gptSectorSize)
	}
	totalSectors := totalSize / gptSectorSize
	if totalSectors < gptPartFirstLBA+1+gptEntriesLBAs+1 {
		return fmt.Errorf("apfs: GPT wrap: image too small (%d sectors)", totalSectors)
	}

	backupHeaderLBA := totalSectors - 1
	backupEntriesLBA := backupHeaderLBA - gptEntriesLBAs
	lastUsable := backupEntriesLBA - 1
	partStart := gptPartFirstLBA
	partEnd := lastUsable

	diskGUID, err := randomGUID()
	if err != nil {
		return err
	}
	partGUID, err := randomGUID()
	if err != nil {
		return err
	}

	// Partition entry array (16 KiB, mostly zero except entry[0]).
	entries := make([]byte, gptMaxEntries*gptEntrySize)
	p := entries[0:]
	copy(p[0:16], appleAPFSPartTypeGUID[:])
	copy(p[16:32], partGUID[:])
	binary.LittleEndian.PutUint64(p[32:], uint64(partStart))
	binary.LittleEndian.PutUint64(p[40:], uint64(partEnd))
	// Apple sets the partition name to "disk image" for hdiutil-created APFS DMGs.
	const partName = "disk image"
	for i, r := range partName {
		off := 56 + i*2
		if off+2 > 128 {
			break
		}
		p[off] = byte(r)
		p[off+1] = byte(r >> 8)
	}
	entriesCRC := crc32.ChecksumIEEE(entries)

	buildHeader := func(currentLBA, backupLBA, entryStartLBA int64) []byte {
		h := make([]byte, gptSectorSize)
		copy(h[0:8], []byte("EFI PART"))
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], gptHeaderSize)
		// h[16:20] = header CRC, filled below
		binary.LittleEndian.PutUint64(h[24:], uint64(currentLBA))
		binary.LittleEndian.PutUint64(h[32:], uint64(backupLBA))
		binary.LittleEndian.PutUint64(h[40:], uint64(gptPartFirstLBA))
		binary.LittleEndian.PutUint64(h[48:], uint64(lastUsable))
		copy(h[56:72], diskGUID[:])
		binary.LittleEndian.PutUint64(h[72:], uint64(entryStartLBA))
		binary.LittleEndian.PutUint32(h[80:], uint32(gptMaxEntries))
		binary.LittleEndian.PutUint32(h[84:], uint32(gptEntrySize))
		binary.LittleEndian.PutUint32(h[88:], entriesCRC)
		hdrCRC := crc32.ChecksumIEEE(h[:gptHeaderSize])
		binary.LittleEndian.PutUint32(h[16:], hdrCRC)
		return h
	}

	primaryHeader := buildHeader(1, backupHeaderLBA, 2)
	backupHeader := buildHeader(backupHeaderLBA, 1, backupEntriesLBA)

	// Protective MBR (sector 0): one 0xEE partition spanning the disk.
	pmbr := make([]byte, gptSectorSize)
	pe := pmbr[446:]
	pe[4] = 0xEE
	pe[5] = 0xFF
	pe[6] = 0xFF
	pe[7] = 0xFF
	binary.LittleEndian.PutUint32(pe[8:], 1)
	sz := uint32(totalSectors - 1)
	if sz > 0xFFFFFFFF {
		sz = 0xFFFFFFFF
	}
	binary.LittleEndian.PutUint32(pe[12:], sz)
	pmbr[510] = 0x55
	pmbr[511] = 0xAA

	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("apfs: GPT wrap: open %s: %w", path, err)
	}
	defer f.Close()

	type region struct {
		off  int64
		data []byte
	}
	for _, w := range []region{
		{0, pmbr},
		{1 * gptSectorSize, primaryHeader},
		{2 * gptSectorSize, entries},
		{backupEntriesLBA * gptSectorSize, entries},
		{backupHeaderLBA * gptSectorSize, backupHeader},
	} {
		if _, err := f.WriteAt(w.data, w.off); err != nil {
			return fmt.Errorf("apfs: GPT wrap: write at 0x%x: %w", w.off, err)
		}
	}
	return nil
}

// gptRandReadFn is the crypto-rand entry point used by randomGUID.
// Tests override it to drive the failure branch; production never does.
var gptRandReadFn = rand.Read

func randomGUID() ([16]byte, error) {
	var g [16]byte
	if _, err := gptRandReadFn(g[:]); err != nil {
		return g, fmt.Errorf("apfs: GPT wrap: random GUID: %w", err)
	}
	// RFC 4122 v4 + variant bits.
	g[6] = (g[6] & 0x0F) | 0x40
	g[8] = (g[8] & 0x3F) | 0x80
	return g, nil
}
