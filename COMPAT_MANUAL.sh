#!/usr/bin/env bash
# COMPAT_MANUAL.sh — manual cells of the APFS cross-compatibility
# protocol described in COMPAT.md.
#
# These procedures cannot be automated cleanly because they:
#   - need GUI authentication (sudo without TTY-attached askpass),
#   - rely on Time Machine being configured (snapshots),
#   - depend on third-party tools (afsctool) that are not on PATH,
#   - or are inherently asynchronous (diskutil apfs encryptVolume
#     schedules work and returns; we have to poll until it finishes).
#
# Each section is numbered to match a cell in COMPAT.md. Copy / paste
# the section into a Terminal session; do not run the whole file as a
# single script — most sections are interactive.
#
# Cleanup: every section explicitly mentions which DMGs / mountpoints
# it leaves behind so you can detach and rm at the end.

set -euo pipefail

# ─── Common setup ────────────────────────────────────────────────────────

work_dir=$(mktemp -d -t apfs-compat-manual)
echo "Working directory: ${work_dir}"
echo "Detach mounted images and rm -rf this directory when you are done."

# ─── F-1 / F-3: APFS FileVault FDE round-trip ────────────────────────────
# Goal: produce an actually APFS-FDE-encrypted volume (not DMG-envelope-
# encrypted) and confirm pkg/go-fde/apfs.Open recognises the bytes.
#
# Why manual: `diskutil apfs encryptVolume` returns immediately and the
# encryption proceeds in the background; polling reliably is awkward
# from `go test`.

f1_apfs_filevault() {
  local pass="${1:-compat-fde-pass}"
  local dmg="${work_dir}/fde.dmg"
  local mp
  mp=$(mktemp -d -t apfs-fde-mnt)

  hdiutil create -size 64m -fs APFS -volname FDETest -ov \
                 -format UDRW -srcfolder "${work_dir}" "${dmg}"
  local dev
  dev=$(hdiutil attach -nobrowse -noautoopen -mountpoint "${mp}" \
                       -readwrite "${dmg}" | awk 'NR==1 {print $1}')

  # Extract the APFS data partition (last column of `diskutil list`).
  local datadev
  datadev=$(diskutil list "${dev}" | awk '/Apple_APFS_ISC|APFS Volume/ {print $NF; exit}')
  echo "APFS volume device: ${datadev}"

  # Encrypt — this returns instantly and re-encrypts in background.
  diskutil apfs encryptVolume "${datadev}" -user disk -passphrase "${pass}"

  # Wait for the conversion to finish; queries run every 5 s.
  while diskutil apfs list "${dev}" | grep -q "Encryption Progress"; do
    sleep 5
    echo "  encryption still in progress…"
  done

  hdiutil detach -force "${dev}"
  rm -rf "${mp}"

  # The DMG file now contains an APFS-FDE-encrypted volume. Read its
  # raw bytes via -nomount and feed them to the Go FDE opener.
  local rawdev
  rawdev=$(hdiutil attach -nomount -noverify -noautofsck "${dmg}" | \
           awk 'NR==1 {print $1}')
  cat "${rawdev}" > "${work_dir}/fde.raw"
  hdiutil detach -force "${rawdev}"

  cd "$(go env GOPATH 2>/dev/null || echo /tmp)"
  cat <<EOF
Now run, in your dev tree:

    cd pkg/go-fde/apfs
    cat <<'GOSCRIPT' | go run -
    package main
    import (
        "fmt"
        "log"
        apfs "github.com/go-fde/apfs"
    )
    func main() {
        d, err := apfs.Open("${work_dir}/fde.raw", []byte("${pass}"))
        if err != nil { log.Fatal(err) }
        defer d.Close()
        fmt.Println("apfsfde.Open succeeded against an Apple-produced FDE container")
    }
GOSCRIPT
EOF
}

# ─── C-3: transparent file compression interop ──────────────────────────
# Goal: hdiutil + afsctool produce a com.apple.decmpfs-compressed file;
# our ReadFileTransparent must return the original bytes.
#
# Why manual: afsctool is not in macOS by default. Install via Homebrew:
#   brew install afsctool

c3_decmpfs() {
  if ! command -v afsctool >/dev/null 2>&1; then
    echo "afsctool not installed; install with: brew install afsctool"
    return 1
  fi
  local dmg="${work_dir}/decmpfs.dmg"
  local mp
  mp=$(mktemp -d -t apfs-cmp-mnt)
  hdiutil create -size 32m -fs APFS -volname DecmpfsTest -ov \
                 -format UDRW -srcfolder "${work_dir}" "${dmg}"
  local dev
  dev=$(hdiutil attach -nobrowse -noautoopen -mountpoint "${mp}" \
                       -readwrite "${dmg}" | awk 'NR==1 {print $1}')

  # Create a payload that compresses well, then compress in place.
  python3 -c 'import sys; sys.stdout.buffer.write(b"compressible chunk " * 5000)' > "${mp}/big.txt"
  afsctool -c "${mp}/big.txt"

  # Extract the raw container for our parser.
  hdiutil detach -force "${dev}"
  rm -rf "${mp}"
  local rawdev
  rawdev=$(hdiutil attach -nomount -noverify -noautofsck "${dmg}" | \
           awk 'NR==1 {print $1}')
  cat "${rawdev}" > "${work_dir}/decmpfs.raw"
  hdiutil detach -force "${rawdev}"

  cat <<EOF
Raw container with a decmpfs-compressed file is at: ${work_dir}/decmpfs.raw
Open it with OpenNative and call ReadFileTransparent on the inode for
"big.txt"; the returned bytes must equal "compressible chunk " repeated
5000 times.
EOF
}

# ─── C-4: snapshot enumeration via tmutil ────────────────────────────────
# Goal: produce a real APFS snapshot via Time Machine and confirm
# ListSnapshots / OpenSnapshot find it.
#
# Why manual: tmutil localsnapshot only works on volumes that the
# user has registered with Time Machine; this is a local-machine
# permission state we cannot grant from a test runner.

c4_tmutil_snapshot() {
  cat <<'EOF'
1. Open System Settings → Time Machine and add the target volume.
2. Run:
       tmutil localsnapshot /Volumes/<your-volume>
3. List the resulting snapshot:
       tmutil listlocalsnapshots /
4. The snapshot lives inside the volume's apfs_snap_meta_tree. Use
   OpenNative + ListSnapshots() to enumerate it; the snapshot's name
   should match the one tmutil printed.
EOF
}

# ─── Driver: parse the first argument and call the matching procedure ────

case "${1:-}" in
  f1) shift; f1_apfs_filevault "$@" ;;
  c3) shift; c3_decmpfs ;;
  c4) shift; c4_tmutil_snapshot ;;
  *)
    cat <<EOF
Usage: $0 <cell> [args]

Cells:
  f1                          APFS FileVault FDE round-trip
  c3                          decmpfs compression interop (needs afsctool)
  c4                          Snapshot enumeration via tmutil

Each cell prints further instructions and leaves artefacts under
${work_dir}.
EOF
    ;;
esac
