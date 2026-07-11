//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestCompatNative_KextReadsOurCompressedFiles is the strong oracle for
// compress-on-write: it formats a container, writes transparently
// compressed files (inline zlib, inline LZVN, and a multi-chunk LZVN
// resource fork) through CreateFileCompressed, commits, then attaches the raw image,
// runs `fsck_apfs -n` (must be clean), mounts it with apfs.kext, and reads
// each file back through the kernel — which transparently decompresses the
// decmpfs content. A byte-exact read-back proves the on-disk structures are
// real, not just self-consistent with our own reader.
func TestCompatNative_KextReadsOurCompressedFiles(t *testing.T) {
	requireTool(t, "hdiutil")
	requireTool(t, "fsck_apfs")
	requireTool(t, "mount_apfs")

	path := filepath.Join(t.TempDir(), "ours.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}
	// 1<<24 (16 MiB) is comfortably within the size range apfs.kext will
	// mount from a synthesised container; larger single-chunk formats are a
	// separate FormatContainer limitation unrelated to compression.
	if err := FormatContainer(path, 1<<24, "CmpKext"); err != nil {
		t.Fatalf("FormatContainer: %v", err)
	}

	// Build the payloads.
	inlineData := bytes.Repeat([]byte("inline decmpfs payload through apfs.kext. "), 20)
	var big bytes.Buffer
	for i := 0; big.Len() < 300*1024; i++ {
		big.WriteString("resource-fork chunked lzvn line ")
		big.WriteByte(byte('0' + i%10))
		big.WriteByte('\n')
	}
	rsrcData := big.Bytes()

	cases := []struct {
		name  string
		codec CompressionCodec
		data  []byte
	}{
		{"inline_zlib.bin", CompressZlib, inlineData},
		{"inline_lzvn.bin", CompressLZVN, inlineData},
		{"rsrc_lzvn.bin", CompressLZVN, rsrcData},
		{"auto.bin", CompressAuto, rsrcData},
	}

	c, err := OpenContainerRW(path)
	if err != nil {
		t.Fatalf("OpenContainerRW: %v", err)
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	for _, tc := range cases {
		if _, err := v.CreateFileCompressedCodec(1, tc.name, tc.data, tc.codec); err != nil {
			t.Fatalf("CreateFileCompressedCodec %s: %v", tc.name, err)
		}
	}
	if err := c.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c.Close()

	// Pass 1: attach and run fsck_apfs -n; it must find no errors (warnings
	// about compressed inodes would fail the run).
	func() {
		out, err := exec.Command("hdiutil", "attach",
			"-nomount", "-noverify",
			"-imagekey", "diskimage-class=CRawDiskImage",
			path,
		).CombinedOutput()
		if err != nil {
			t.Fatalf("hdiutil attach (fsck pass): %v\n%s", err, out)
		}
		dev := parseHdiutilAttachContainer(t, out)
		defer exec.Command("hdiutil", "detach", "-force", dev).Run()
		fsckOut, fsckErr := exec.Command("fsck_apfs", "-n", dev).CombinedOutput()
		if fsckErr != nil {
			t.Fatalf("fsck_apfs -n on compressed container failed: %v\n%s", fsckErr, fsckOut)
		}
		if strings.Contains(string(fsckOut), "warning:") {
			t.Fatalf("fsck_apfs emitted warnings on compressed container:\n%s", fsckOut)
		}
		t.Logf("fsck_apfs clean (no warnings) on compressed container:\n%s", fsckOut)
	}()

	// Pass 2: fresh attach, mount with apfs.kext, read every file back.
	out, err := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		path,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach (mount pass): %v\n%s", err, out)
	}
	containerDev := parseHdiutilAttachContainer(t, out)
	t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", containerDev).Run() })

	volDev := containerDev + "s1"
	mnt := t.TempDir()
	if mountOut, err := exec.Command("mount_apfs", volDev, mnt).CombinedOutput(); err != nil {
		t.Fatalf("mount_apfs %s: %v\n%s", volDev, err, mountOut)
	}
	t.Cleanup(func() { exec.Command("diskutil", "unmount", mnt).Run() })

	for _, tc := range cases {
		p := filepath.Join(mnt, tc.name)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("kext ReadFile %s: %v", tc.name, err)
		}
		if !bytes.Equal(got, tc.data) {
			t.Fatalf("%s: kext read-back mismatch (got %d bytes, want %d)", tc.name, len(got), len(tc.data))
		}
		// The kernel must report the file as compressed (UF_COMPRESSED).
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatalf("Lstat %s: %v", tc.name, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("%s: no syscall.Stat_t", tc.name)
		}
		if st.Flags&bsdFlagUFCompressed == 0 {
			t.Fatalf("%s: UF_COMPRESSED not set (flags=0x%x)", tc.name, st.Flags)
		}
		if uint64(fi.Size()) != uint64(len(tc.data)) {
			t.Fatalf("%s: kext st_size=%d want %d", tc.name, fi.Size(), len(tc.data))
		}
		t.Logf("%s: kext transparently decompressed %d bytes, UF_COMPRESSED set.", tc.name, len(got))
	}
}
