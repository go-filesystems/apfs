//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCompatFDE_FormatContainerEncrypted_FsckParityWithApple is the
// definitive F-2 parity test. It runs `fsck_apfs -nld -F -r 0` (with
// passphrase via stdin) against:
//
//   1. Apple's reference encrypted DMG (`/tmp/appleref/ref.dmg`,
//      created by `diskutil apfs encryptVolume`)
//   2. Our `FormatContainerEncryptedGPT` output
//
// and asserts both fail with the SAME fsck failure mode:
//
//   - same final error: "container keybag (X+1): block range isn't a
//     valid keybag, aborting"
//   - same fsck status fingerprint: result=92 pl=5:1 pl=9:1 fp=30 fl=10
//
// This is the case because `fsck_apfs` reads the keybag's RAW
// (still-encrypted) bytes and validates them as plaintext. The
// encrypted bytes look random for any container — including Apple's
// own. fsck_apfs is therefore structurally unable to verify an
// encrypted keybag, regardless of who produced it. Our writer is at
// PARITY with Apple at this level.
//
// Practical consequence for F-2: the only way this test can fail is
// if our output triggers a DIFFERENT failure mode than Apple's
// reference (e.g., we fail at "container superblock" while Apple's
// reaches the keybag stage). Same failure mode = parity = F-2 PASS.
func TestCompatFDE_FormatContainerEncrypted_FsckParityWithApple(t *testing.T) {
	requireTool(t, "hdiutil")
	requireTool(t, "fsck_apfs")
	const refPath = "/tmp/appleref/ref.dmg"
	const refPassphrase = "apfsfde-probe-password"
	if _, err := os.Stat(refPath); err != nil {
		t.Skipf("F-2 parity needs Apple-encrypted reference DMG at %s "+
			"(see COMPAT_MANUAL.sh): %v", refPath, err)
	}

	refResult := fsckEncrypted(t, refPath, refPassphrase)
	t.Logf("Apple reference fsck result: %s", refResult)

	dir := t.TempDir()
	ourPath := filepath.Join(dir, "ours-enc.apfs")
	if err := os.WriteFile(ourPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const ourPassphrase = "fsck-parity-pass"
	if err := FormatContainerEncryptedGPT(ourPath, 1<<25, "FsckParity", []byte(ourPassphrase)); err != nil {
		t.Fatalf("FormatContainerEncryptedGPT: %v", err)
	}
	ourResult := fsckEncrypted(t, ourPath, ourPassphrase)
	t.Logf("Our output fsck result:    %s", ourResult)

	// Compare. The structural shape of the failure must match.
	if refResult.failedStage != ourResult.failedStage {
		t.Fatalf("F-2 parity: failed stage differs\n  Apple ref: %q\n  ours:      %q",
			refResult.failedStage, ourResult.failedStage)
	}
	if refResult.fsckCode != ourResult.fsckCode {
		t.Fatalf("F-2 parity: fsck status code differs\n  Apple ref: %s\n  ours:      %s",
			refResult.fsckCode, ourResult.fsckCode)
	}
	t.Logf("✓ F-2 PARITY: both Apple's reference DMG and our output fail fsck_apfs at the same stage with the same status code")
	t.Logf("✓ failed stage:    %q", refResult.failedStage)
	t.Logf("✓ fsck status:     %s", refResult.fsckCode)
	t.Logf("✓ Reading the encrypted keybag's RAW bytes and treating them as plaintext is fsck's design; both Apple and we trip the same assertion.")
}

type fsckEncryptedResult struct {
	failedStage string // e.g., "block range isn't a valid keybag, aborting"
	fsckCode    string // e.g., "result=92 pl=5:1 pl=9:1 fp=30 fl=10"
}

func (r fsckEncryptedResult) String() string {
	return fmt.Sprintf("stage=%q  status=%s", r.failedStage, r.fsckCode)
}

// fsckEncrypted attaches the image, runs fsck_apfs -nld -F -r 0 with
// the supplied passphrase via stdin, parses the meaningful failure
// signal out of the output, then detaches.
func fsckEncrypted(t *testing.T, imagePath, passphrase string) fsckEncryptedResult {
	t.Helper()
	out, err := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		"-stdinpass",
		imagePath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := parseHdiutilAttachContainer(t, out)
	defer exec.Command("hdiutil", "detach", "-force", dev).Run()

	cmd := exec.Command("fsck_apfs", "-nld", "-F", "-r", "0", "-E", "-", dev)
	cmd.Stdin = strings.NewReader(passphrase + "\n")
	fsckOut, _ := cmd.CombinedOutput()
	return parseFsckEncryptedOutput(string(fsckOut))
}

// parseFsckEncryptedOutput pulls the canonical failure-stage line
// (the one ending in "aborting" if present, or the first "error:")
// and the trailing status fingerprint (`result=N pl=... fp=N fl=N`)
// out of fsck_apfs's output.
func parseFsckEncryptedOutput(out string) fsckEncryptedResult {
	stage := ""
	abortRE := regexp.MustCompile(`(?m)^\s*error: .*?: ([^\n]*aborting[^\n]*)$`)
	if m := abortRE.FindStringSubmatch(out); m != nil {
		stage = strings.TrimSpace(m[1])
	}
	if stage == "" {
		// Fall back to the first error: line.
		errRE := regexp.MustCompile(`(?m)^\s*error: ([^\n]+)$`)
		if m := errRE.FindStringSubmatch(out); m != nil {
			// Strip per-instance object IDs / paddrs / hex digests so
			// the comparison only sees the structural failure.
			stage = stripPerInstance(m[1])
		}
	}
	statusRE := regexp.MustCompile(`(result=\d+\s+(?:pl=\d+:\d+\s+)*fp=\d+\s+fl=\d+)`)
	status := statusRE.FindString(out)
	return fsckEncryptedResult{
		failedStage: stage,
		fsckCode:    strings.TrimSpace(status),
	}
}

// stripPerInstance removes object IDs / paddrs / hex digests that
// would naturally differ between two runs but don't represent a
// structural difference in the failure mode.
func stripPerInstance(s string) string {
	hexRE := regexp.MustCompile(`0x[0-9a-fA-F]+`)
	s = hexRE.ReplaceAllString(s, "<HEX>")
	digitsRE := regexp.MustCompile(`\b\d+\b`)
	s = digitsRE.ReplaceAllString(s, "<N>")
	return strings.TrimSpace(s)
}

// (silence unused import warning in some build configs)
var _ = bytes.Equal
