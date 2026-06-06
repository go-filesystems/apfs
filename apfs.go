package filesystem_apfs

// apfs.go — top-level entry points for the APFS filesystem package.
// `Open`, `OpenWithKeys`, and `Format` wrap the real-APFS
// `*Container` + `*Volume` API via the `driver` adapter in
// driver.go. On macOS, `Open`/`OpenWithKeys` fall back to
// `hdiutil attach` when the file is not a parseable real APFS
// container, so arbitrary Apple-produced DMGs are still readable.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	filesystem "github.com/go-filesystems/interface"
)

// ErrNoHeader is returned by Open when the file is neither a real
// APFS container nor (on darwin) a hdiutil-mountable image.
var ErrNoHeader = errors.New("apfs: no header")

// FormatConfig configures Format. The Encryption field accepts an
// `*FDEConfig` to produce a FileVault-encrypted APFS container.
type FormatConfig struct {
	Label      string
	Encryption *FDEConfig
}

// FDEConfig holds the passphrase for FileVault-encrypted format.
type FDEConfig struct {
	Passphrase string
}

// Format creates a fresh APFS container at `path` and returns a
// filesystem.Filesystem wrapping its first volume. The file is
// auto-created if missing. For encrypted containers, populate
// cfg.Encryption with the passphrase.
func Format(path string, sizeBytes int64, cfg FormatConfig) (filesystem.Filesystem, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, fmt.Errorf("apfs: create %s: %w", path, err)
		}
	} else if err != nil {
		return nil, err
	}
	label := cfg.Label
	if label == "" {
		label = "APFS"
	}
	if cfg.Encryption != nil {
		if err := FormatContainerEncrypted(path, sizeBytes, label, []byte(cfg.Encryption.Passphrase)); err != nil {
			return nil, err
		}
		return openContainerAsFilesystem(path, []byte(cfg.Encryption.Passphrase))
	}
	if err := FormatContainer(path, sizeBytes, label); err != nil {
		return nil, err
	}
	return openContainerAsFilesystem(path, nil)
}

// Open opens an existing APFS container at `path`. Resolution order:
//
//  1. Try real APFS (pure Go, all platforms).
//  2. Try FileVault-encrypted real APFS (requires a passphrase, see
//     OpenWithKeys for that variant).
//  3. On darwin: hdiutil-mount the image and proxy operations to
//     the mountpoint.
//
// Returns ErrNoHeader when nothing matches.
//
// The partIndex parameter is accepted for API compatibility but
// currently ignored (the pure-Go reader uses the container's first
// volume; GPT-partitioned images are handled transparently by
// OpenContainerAuto in fs.go).
func Open(imagePath string, partIndex int) (filesystem.Filesystem, error) {
	_ = partIndex
	if fs, err := openContainerAsFilesystem(imagePath, nil); err == nil {
		return fs, nil
	}
	if runtime.GOOS == "darwin" {
		mnt, dev, merr := attachImage(imagePath)
		if merr == nil {
			return &driver{mountpoint: mnt, dev: dev}, nil
		}
	}
	return nil, ErrNoHeader
}

// OpenWithKeys opens an APFS container, trying the supplied keys
// against the FileVault keybag (if encrypted). For unencrypted
// images the keys are ignored. Falls back to hdiutil-mount on
// darwin.
func OpenWithKeys(imagePath string, partIndex int, keys ...string) (filesystem.Filesystem, error) {
	_ = partIndex
	// Try unencrypted real APFS first.
	if fs, err := openContainerAsFilesystem(imagePath, nil); err == nil {
		return fs, nil
	}
	// Try FileVault FDE with each supplied passphrase.
	for _, k := range keys {
		if fs, err := openContainerAsFilesystem(imagePath, []byte(k)); err == nil {
			return fs, nil
		}
	}
	// Darwin fallback.
	if runtime.GOOS == "darwin" {
		mnt, dev, merr := attachImage(imagePath)
		if merr == nil {
			return &driver{mountpoint: mnt, dev: dev}, nil
		}
	}
	return nil, ErrNoHeader
}

// openContainerAsFilesystem is the shared opening logic. If
// passphrase is non-nil, the container is treated as FileVault-
// encrypted; otherwise unencrypted APFS is assumed.
func openContainerAsFilesystem(path string, passphrase []byte) (filesystem.Filesystem, error) {
	if passphrase != nil {
		// FileVault-encrypted path. apfs_fde.go::OpenFDE returns a
		// driver bound to the decrypted container.
		return openEncryptedFilesystem(path, passphrase)
	}
	c, err := OpenContainerRWAuto(path)
	if err != nil {
		// Read-only fallback for non-writable images.
		ro, roerr := OpenContainerAuto(path)
		if roerr != nil {
			return nil, err
		}
		v, verr := ro.OpenVolume(0)
		if verr != nil {
			ro.Close()
			return nil, verr
		}
		return &driver{c: ro, v: v}, nil
	}
	v, err := c.OpenVolume(0)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &driver{c: c, v: v}, nil
}

// FormatAppleDmg creates a real Apple DMG formatted as APFS using `hdiutil`.
// This is used by diskimage on macOS to produce images mountable by native tools.
func FormatAppleDmg(path string, sizeBytes int64, cfg FormatConfig) error {
	// hdiutil expects a human size, use megabytes.
	mb := (sizeBytes + (1 << 20) - 1) / (1 << 20)
	sizeArg := fmt.Sprintf("%dm", mb)
	tmpDir, err := os.MkdirTemp("", "hdi-srcfolder-*")
	if err != nil {
		return fmt.Errorf("apfs: tempdir for hdiutil: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	label := cfg.Label
	if label == "" {
		label = "APFS"
	}
	args := []string{"create", "-size", sizeArg, "-fs", "APFS", "-volname", label, "-ov", "-format", "UDRW", "-srcfolder", tmpDir, path}
	out, err := exec.Command("hdiutil", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apfs: hdiutil create failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	mp, dev, aerr := attachImage(path)
	if aerr != nil {
		return fmt.Errorf("apfs: attach failed after create: %v: %s", aerr, strings.TrimSpace(string(out)))
	}
	if mp != "" {
		_ = detachImage(dev, mp)
		return nil
	}
	if dev == "" {
		return fmt.Errorf("apfs: no device found after attach")
	}
	if out, err = exec.Command("diskutil", "eraseVolume", "APFS", label, dev).CombinedOutput(); err == nil {
		_ = exec.Command("hdiutil", "detach", "-force", dev).Run()
		return nil
	}
	out, err = exec.Command("diskutil", "apfs", "createContainer", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apfs: diskutil format failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	re := regexp.MustCompile(`(/dev/disk[0-9]+s?[0-9]*)`)
	m := re.FindString(string(out))
	container := m
	if container == "" {
		container = dev
	}
	out, err = exec.Command("diskutil", "apfs", "addVolume", container, "APFS", label).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apfs: diskutil addVolume failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("hdiutil", "detach", "-force", container).Run()
	return nil
}

// attachImage mounts imagePath via hdiutil and returns the mountpoint
// + device node. Used by Open's darwin fallback.
func attachImage(imagePath string) (string, string, error) {
	cmd := exec.Command("hdiutil", "attach", "-plist", "-nobrowse", "-noautoopen", "-readwrite", imagePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("apfs: hdiutil attach failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	pl := exec.Command("plutil", "-convert", "json", "-o", "-", "-")
	pl.Stdin = bytes.NewReader(out)
	jout, jerr := pl.CombinedOutput()
	if jerr == nil {
		var parsed interface{}
		if err := json.Unmarshal(jout, &parsed); err == nil {
			if arr, ok := parsed.([]interface{}); ok {
				for _, item := range arr {
					if dict, ok := item.(map[string]interface{}); ok {
						if ses, ok := dict["system-entities"].([]interface{}); ok {
							for _, se := range ses {
								if ent, ok := se.(map[string]interface{}); ok {
									if mpv, ok := ent["mount-point"]; ok {
										if mp, ok := mpv.(string); ok && mp != "" {
											dev := ""
											if devv, ok := ent["dev-entry"].(string); ok {
												dev = devv
											}
											return mp, dev, nil
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	// XML-plist textual fallback.
	s := string(out)
	if strings.Contains(s, "<plist") {
		for {
			i := strings.Index(s, "<key>mount-point</key>")
			if i == -1 {
				break
			}
			ss := s[i:]
			si := strings.Index(ss, "<string>")
			ei := strings.Index(ss, "</string>")
			if si != -1 && ei != -1 && ei > si {
				mp := ss[si+len("<string>") : ei]
				dictStart := strings.LastIndex(s[:i], "<dict>")
				dictEnd := strings.Index(s[i:], "</dict>")
				dev := ""
				if dictStart != -1 && dictEnd != -1 {
					block := s[dictStart : i+dictEnd]
					di := strings.Index(block, "<key>dev-entry</key>")
					if di != -1 {
						b := block[di:]
						dsi := strings.Index(b, "<string>")
						dei := strings.Index(b, "</string>")
						if dsi != -1 && dei != -1 && dei > dsi {
							dev = b[dsi+len("<string>") : dei]
						}
					}
				}
				return strings.TrimSpace(mp), strings.TrimSpace(dev), nil
			}
			s = s[i+1:]
		}
	}
	// Textual fallback.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			last := fields[len(fields)-1]
			if strings.HasPrefix(last, "/") {
				dev := fields[0]
				return last, dev, nil
			}
		}
	}
	return "", "", fmt.Errorf("apfs: hdiutil attach output parse failed: %s", strings.TrimSpace(string(out)))
}

func detachImage(dev, mountpoint string) error {
	if dev != "" {
		exec.Command("hdiutil", "detach", "-force", dev).Run()
	}
	if mountpoint != "" {
		os.RemoveAll(mountpoint)
	}
	return nil
}
