//go:build darwin && darwin_compat

package filesystem_apfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProbe_KextLogsOnFsckFailure formats an encrypted GPT-wrapped
// container, attaches it, runs fsck_apfs with verbose+debug flags,
// then dumps the macOS unified log for the apfs subsystem to capture
// the internal kext/fsck error messages (which usually don't surface
// to fsck's stdout). The output is what we need to identify the
// remaining "Bad message" gating check.
//
// Run with:
//
//	GOWORK=off go test -tags=darwin_compat -count=1 \
//	    -run TestProbe_KextLogsOnFsckFailure . -v
func TestProbe_KextLogsOnFsckFailure(t *testing.T) {
	requireTool(t, "hdiutil")
	requireTool(t, "fsck_apfs")
	requireTool(t, "log")

	// Persist the image outside t.TempDir() so it stays around after the
	// test ends — useful for follow-up manual probing.
	persistDir := "/tmp/apfs-fsck-probe"
	if err := os.MkdirAll(persistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(persistDir, "ours-enc-gpt.apfs")
	os.Remove(path)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const passphrase = "FormatEncGPT-darwin-test-pass"
	if err := FormatContainerEncryptedGPT(path, 1<<25, "FsckProbe", []byte(passphrase)); err != nil {
		t.Fatalf("FormatContainerEncryptedGPT: %v", err)
	}
	t.Logf("encrypted image persisted at %s (size=32 MiB)", path)

	// Mark the start time so we can pull only logs from this run.
	startTime := time.Now()

	// Attach.
	cmd := exec.Command("hdiutil", "attach",
		"-nomount", "-noverify",
		"-imagekey", "diskimage-class=CRawDiskImage",
		"-stdinpass",
		path,
	)
	cmd.Stdin = strings.NewReader(passphrase + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hdiutil attach: %v\n%s", err, out)
	}
	dev := parseHdiutilAttachContainer(t, out)
	t.Cleanup(func() { exec.Command("hdiutil", "detach", "-force", dev).Run() })
	t.Logf("attached at %s", dev)

	// Trigger diskutil apfs list (likely to surface kext-internal
	// messages about why it can't enumerate volumes).
	if listOut, _ := exec.Command("diskutil", "apfs", "list", dev).CombinedOutput(); len(listOut) > 0 {
		t.Logf("diskutil apfs list:\n%s", listOut)
	}

	// Run fsck_apfs with debug. -l requires either -n or -q; -d enables
	// extra debug. -E - writes warnings to stdout.
	fsckCmd := exec.Command("fsck_apfs", "-nld", "-E", "-", dev)
	fsckOut, fsckErr := fsckCmd.CombinedOutput()
	t.Logf("fsck_apfs -nld %s err=%v\n%s", dev, fsckErr, fsckOut)

	// Pull the unified-log entries since startTime that match the apfs
	// subsystem. macOS by default redacts sensitive fields with
	// "<private>"; we ask the user to enable private-data logging if
	// they have access. Even with redaction, the structure of the
	// errors usually surfaces.
	until := time.Since(startTime).Round(time.Second) + 1*time.Second
	logCmd := exec.Command("log", "show",
		"--last", fmt.Sprintf("%ds", int(until.Seconds())),
		"--predicate", "subsystem == \"com.apple.apfs\" OR process == \"fsck_apfs\" OR process == \"diskmanagementd\" OR process == \"diskarbitrationd\"",
		"--info", "--debug",
	)
	logOut, logErr := logCmd.CombinedOutput()
	t.Logf("=== log show (last ~%s, apfs subsystem + diskutil daemons) ===\n%s\n--- log err: %v ---", until, logOut, logErr)

	// Also pull the LAST 200 lines from the system.log style buffer
	// just in case the unified log filter missed something.
	syslogCmd := exec.Command("log", "show", "--last", fmt.Sprintf("%ds", int(until.Seconds())), "--info", "--debug")
	syslogOut, _ := syslogCmd.Output()
	if len(syslogOut) > 0 {
		// Filter for likely-relevant lines.
		var relevant []string
		for _, line := range strings.Split(string(syslogOut), "\n") {
			l := strings.ToLower(line)
			if strings.Contains(l, "apfs") || strings.Contains(l, "keybag") ||
				strings.Contains(l, "fsck") || strings.Contains(l, "encryption") ||
				strings.Contains(l, "bad message") || strings.Contains(l, "ebadmsg") {
				relevant = append(relevant, line)
			}
		}
		if len(relevant) > 0 {
			t.Logf("=== unified-log lines mentioning apfs/keybag/fsck/encryption/EBADMSG (~%d) ===\n%s",
				len(relevant), strings.Join(relevant, "\n"))
		}
	}
}
