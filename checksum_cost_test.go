package filesystem_apfs

import (
	"testing"
	"time"
)

// TestVerifyObjectBlockCostBounded holds the per-read cost of o_cksum
// verification. Every object read verifies, and the write path re-reads the
// tree for each operation, so a slow checksum multiplies through the whole
// suite: with the word loop instrumented by the race detector the full race
// run exceeded the CI job's one hour limit (TestDeleteAllInLargeMultiLevelTree
// took 2.4x longer). The bound is generous (about 100 us per 4 KiB block,
// well above the measured cost in every mode) so only a regression of that
// size trips it, and it is asserted on elapsed time so a runaway cannot pass
// silently.
func TestVerifyObjectBlockCostBounded(t *testing.T) {
	const blocks = 20000
	block := make([]byte, 4096)
	for i := range block {
		block[i] = byte(i * 31)
	}
	sealBlock(block)
	start := time.Now()
	for i := 0; i < blocks; i++ {
		if err := verifyObjectBlock(uint64(i), block); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}
	if d, limit := time.Since(start), blocks*100*time.Microsecond; d > limit {
		t.Fatalf("verifying %d blocks took %v, limit %v", blocks, d, limit)
	}
}
