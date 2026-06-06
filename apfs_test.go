package filesystem_apfs

import (
	"testing"
)

func TestFormatOpenWriteRead(t *testing.T) {
	tmp := t.TempDir()
	img := tmp + "/img.apfs"
	fs, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	defer fs.Close()

	data := []byte("hello apfs")
	if err := fs.WriteFile("/hello.txt", data, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	got, err := fs.ReadFile("/hello.txt")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch: got %q want %q", string(got), string(data))
	}

	st, err := fs.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if st.Size() != uint64(len(data)) {
		t.Fatalf("Stat size mismatch: got %d want %d", st.Size(), len(data))
	}

	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == "hello.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected hello.txt in ListDir")
	}
}

func TestRenameDeleteDir(t *testing.T) {
	tmp := t.TempDir()
	img := tmp + "/img.apfs"
	fs, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	defer fs.Close()

	if err := fs.MkDir("/dir", 0o755); err != nil {
		t.Fatalf("MkDir failed: %v", err)
	}
	if err := fs.WriteFile("/dir/file.txt", []byte("data"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := fs.Rename("/dir/file.txt", "/file2.txt"); err != nil {
		t.Fatalf("Rename failed: %v", err)
	}
	if _, err := fs.Stat("/file2.txt"); err != nil {
		t.Fatalf("Stat after rename failed: %v", err)
	}
	if err := fs.DeleteFile("/file2.txt"); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	if err := fs.DeleteDir("/dir"); err != nil {
		t.Fatalf("DeleteDir failed: %v", err)
	}
	entries, err := fs.ListDir("/")
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	for _, e := range entries {
		if e.Name() == "dir" {
			t.Fatalf("dir still present after DeleteDir")
		}
	}
}

func TestIndexPersistence(t *testing.T) {
	tmp := t.TempDir()
	img := tmp + "/img.apfs"
	_, err := Format(img, 1<<20, FormatConfig{})
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	fs1, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := fs1.WriteFile("/persist.txt", []byte("persist"), 0o644); err != nil {
		fs1.Close()
		t.Fatalf("WriteFile failed: %v", err)
	}
	fs1.Close()

	fs2, err := Open(img, 0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer fs2.Close()
	got, err := fs2.ReadFile("/persist.txt")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != "persist" {
		t.Fatalf("persistence mismatch: got %q", string(got))
	}
}
