module github.com/go-filesystems/apfs

go 1.26.0

require github.com/go-filesystems/interface v0.0.0

require github.com/go-fde/apfs v0.0.0

require (
	github.com/go-compressions/lzfse v0.0.0
	golang.org/x/crypto v0.50.0
)

require golang.org/x/sys v0.43.0 // indirect

// Monorepo-only: published-repo equivalents are pinned via `require`
// to tagged versions when the umbrella publish.sh runs. These three
// directives let `task ci` work in-tree with GOWORK=off.
replace github.com/go-compressions/lzfse => ../../go-compressions/lzfse
replace github.com/go-fde/apfs           => ../../go-fde/apfs
replace github.com/go-filesystems/interface => ../interface
