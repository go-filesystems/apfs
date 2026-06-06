package filesystem_apfs

// driver_mount.go — mount-backed proxy methods used by `driver`
// when the container was opened via hdiutil-attach on macOS (the
// `mountpoint != ""` branch of every Filesystem method).
//
// These wrap the OS filesystem at the given mountpoint; they're not
// strictly darwin-only (any mounted directory would work) but in
// practice the only constructor that produces a mountpoint is
// `attachImage` on darwin.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-filesystems/interface"
)

// mountPathToReal resolves `p` (a `filesystem.Filesystem`-style
// logical path) to the corresponding absolute path under
// `mountpoint`. The root path "/" or "" maps to the mountpoint itself.
func mountPathToReal(mountpoint, p string) string {
	clean := strings.TrimPrefix(p, "/")
	if clean == "" {
		return mountpoint
	}
	return filepath.Join(mountpoint, clean)
}

func mountModeReadFile(mountpoint, p string) ([]byte, error) {
	if strings.TrimPrefix(p, "/") == "" {
		return nil, fmt.Errorf("apfs: %q is a directory", p)
	}
	return os.ReadFile(mountPathToReal(mountpoint, p))
}

func mountModeListDir(mountpoint, p string) ([]filesystem.DirEntry, error) {
	real := mountPathToReal(mountpoint, p)
	dirents, err := os.ReadDir(real)
	if err != nil {
		return nil, err
	}
	out := make([]filesystem.DirEntry, 0, len(dirents))
	for _, d := range dirents {
		var ft uint8 = 8 // DT_REG
		if d.IsDir() {
			ft = 4 // DT_DIR
		} else if d.Type()&os.ModeSymlink != 0 {
			ft = 10 // DT_LNK
		}
		out = append(out, filesystem.NewDirEntry(0, d.Name(), ft))
	}
	return out, nil
}

func mountModeStat(mountpoint, p string) (filesystem.Stat, error) {
	real := mountPathToReal(mountpoint, p)
	fi, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	mode := uint16(0o100644)
	if fi.IsDir() {
		mode = 0o040755
	}
	return filesystem.NewStat(mode, uint64(fi.Size()), 0), nil
}

func mountModeWriteFile(mountpoint, p string, data []byte, perm os.FileMode) error {
	real := mountPathToReal(mountpoint, p)
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		return err
	}
	return os.WriteFile(real, data, perm)
}

func mountModeReadLink(mountpoint, p string) (string, error) {
	return os.Readlink(mountPathToReal(mountpoint, p))
}

func mountModeMkDir(mountpoint, p string, perm os.FileMode) error {
	real := mountPathToReal(mountpoint, p)
	if real == mountpoint {
		return nil
	}
	return os.MkdirAll(real, perm)
}

func mountModeDeleteFile(mountpoint, p string) error {
	return os.Remove(mountPathToReal(mountpoint, p))
}

func mountModeDeleteDir(mountpoint, p string) error {
	real := mountPathToReal(mountpoint, p)
	if real == mountpoint {
		// Wipe everything under the mountpoint but keep the
		// mountpoint itself.
		entries, err := os.ReadDir(real)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := os.RemoveAll(filepath.Join(real, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return os.RemoveAll(real)
}

func mountModeRename(mountpoint, oldPath, newPath string) error {
	return os.Rename(mountPathToReal(mountpoint, oldPath), mountPathToReal(mountpoint, newPath))
}
