package lz4_test

import (
	"bytes"
	"testing"

	"github.com/pierrec/lz4/v4"
)

func TestJoinBlocks(t *testing.T) {
	left := bytes.Repeat([]byte("abcdefg-"), 2000)
	right := bytes.Repeat([]byte("xyz123+"), 2000)
	cl := make([]byte, lz4.CompressBlockBound(len(left)))
	nl, err := lz4.CompressBlock(left, cl, nil)
	if err != nil || nl == 0 {
		t.Fatalf("compress left: n=%d err=%v", nl, err)
	}
	cr := make([]byte, lz4.CompressBlockBound(len(right)))
	nr, err := lz4.CompressBlock(right, cr, nil)
	if err != nil || nr == 0 {
		t.Fatalf("compress right: n=%d err=%v", nr, err)
	}
	cl, cr = cl[:nl], cr[:nr]

	joined, err := lz4.JoinBlocks(cl, cr, len(left)+len(right))
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, left...), right...)
	got := make([]byte, len(want))
	m, err := lz4.UncompressBlock(joined, got)
	if err != nil || m != len(want) || !bytes.Equal(got, want) {
		t.Fatalf("joined block: n=%d err=%v match=%v", m, err, bytes.Equal(got, want))
	}

	// The bound is enforced before output allocation.
	if _, err := lz4.JoinBlocks(cl, cr, len(want)-1); err == nil {
		t.Fatal("expected error when the merged size exceeds the bound")
	}
	// Empty compressed slices are invalid; empty data is a zero token.
	if _, err := lz4.JoinBlocks(nil, cr, len(want)); err == nil {
		t.Fatal("expected error for an empty left block")
	}
	out, err := lz4.JoinBlocks([]byte{0}, []byte{0}, 0)
	if err != nil || len(out) != 1 || out[0] != 0 {
		t.Fatalf("join empty blocks: % x, err=%v", out, err)
	}
}
