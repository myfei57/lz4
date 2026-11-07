package lz4_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/pierrec/lz4/v4"
)

// TestCompressorOptimalAPI exercises the public block wrapper, its errors and
// deterministic reuse. Minimality itself is tested against an exhaustive
// encoder in internal/lz4block.
func TestCompressorOptimalAPI(t *testing.T) {
	if lz4.OptimalMaxInputSize != 8<<10 {
		t.Fatalf("OptimalMaxInputSize = %d", lz4.OptimalMaxInputSize)
	}
	if lz4.OptimalMaxWorkspace < lz4.OptimalMaxInputSize {
		t.Fatalf("OptimalMaxWorkspace = %d", lz4.OptimalMaxWorkspace)
	}

	src := bytes.Repeat([]byte("the quick brown fox "), 200) // 4000 bytes
	encode := func(c *lz4.CompressorOptimal) []byte {
		dst := make([]byte, lz4.CompressBlockBound(len(src)))
		n, err := c.CompressBlock(src, dst)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), dst[:n]...)
	}

	var c lz4.CompressorOptimal
	z := encode(&c)
	dec := make([]byte, len(src))
	n, err := lz4.UncompressBlock(z, dec)
	if err != nil || n != len(src) || !bytes.Equal(dec, src) {
		t.Fatalf("roundtrip: n=%d err=%v", n, err)
	}
	if again := encode(&c); !bytes.Equal(again, z) {
		t.Fatal("reuse changed output")
	}
	c.Reset()
	if again := encode(&c); !bytes.Equal(again, z) {
		t.Fatal("Reset changed output")
	}

	// Input beyond the limit fails with the exported error.
	if _, err := c.CompressBlock(make([]byte, lz4.OptimalMaxInputSize+1), make([]byte, 16)); !errors.Is(err, lz4.ErrOptimalInputTooLarge) {
		t.Fatalf("err = %v", err)
	}
	// A short destination fails with the recognizable short-buffer error,
	// distinct from the other compressors' error.
	if _, err := c.CompressBlock(src, z[:len(z)-1]); !errors.Is(err, lz4.ErrOptimalShortBuffer) {
		t.Fatalf("err = %v", err)
	}
	// It must be recognizable on its own, distinct from the decoder's error.
	if errors.Is(lz4.ErrOptimalShortBuffer, lz4.ErrInvalidSourceShortBuffer) {
		t.Fatal("optimal short-buffer error is indistinguishable from the decoder error")
	}

	// The pooled entry point produces the same bytes.
	dst := make([]byte, lz4.CompressBlockBound(len(src)))
	m, err := lz4.CompressBlockOptimal(src, dst)
	if err != nil || !bytes.Equal(dst[:m], z) {
		t.Fatalf("CompressBlockOptimal: m=%d err=%v", m, err)
	}
}
