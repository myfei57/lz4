package lz4block_test

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/pierrec/lz4/v4/internal/lz4block"
	"github.com/pierrec/lz4/v4/internal/lz4errors"
)

// extBytes counts the length extension bytes for a length value, written in
// the style of the block format rather than the implementation's formula, so
// the two are independently derived.
func extBytes(value int) int {
	if value < 15 {
		return 0
	}
	n := 0
	for v := value - 15; ; n++ {
		if v < 255 {
			return n + 1
		}
		v -= 255
	}
}

func literalOnlySize(n int) int { return 1 + extBytes(n) + n }

// oracleMinSize is an independent exhaustive encoder for short inputs. It
// enumerates every legal match start, distance and length, with memoization
// by input position, and returns the minimum number of encoded bytes.
//
// Match legality mirrors the block format:
//   - a match starts at s <= n-12 and ends at or before n-5, so the last
//     match starts 12 bytes before the end and the last 5 bytes are literals;
//   - the offset d is in [1,s];
//   - comparing src[s:] with src[s-d:] directly, including positions past s,
//     models overlapping copies such as an offset-1 run.
func oracleMinSize(src []byte) int {
	n := len(src)
	memo := make([]int, n+1)
	for i := range memo {
		memo[i] = -1
	}
	var minFrom func(i int) int
	minFrom = func(i int) int {
		if memo[i] >= 0 {
			return memo[i]
		}
		best := literalOnlySize(n - i)
		for s := i; s <= n-12; s++ {
			prefix := 1 + extBytes(s-i) + (s - i) // token, literal extension, literals
			for d := 1; d <= s; d++ {
				limit := n - 5 - s
				l := 0
				for l < limit && src[s+l] == src[s-d+l] {
					l++
				}
				for m := 4; m <= l; m++ {
					// prefix + offset + match extension, then the rest.
					v := prefix + 2 + extBytes(m-4) + minFrom(s+m)
					if v < best {
						best = v
					}
				}
			}
		}
		memo[i] = best
		return best
	}
	return minFrom(0)
}

// sequence is one decoded block sequence: a match when offset > 0, otherwise
// the final literal-only sequence.
type sequence struct {
	litLen, matchLen, offset int
}

// parseSequences decodes just the structure of an LZ4 block, independently of
// the package decoder.
func parseSequences(t *testing.T, z []byte) []sequence {
	t.Helper()
	var out []sequence
	i := 0
	for i < len(z) {
		tok := z[i]
		i++
		l := int(tok >> 4)
		if l == 15 {
			for {
				x := z[i]
				i++
				l += int(x)
				if x != 255 {
					break
				}
			}
		}
		i += l
		if i == len(z) {
			out = append(out, sequence{litLen: l})
			break
		}
		if i+2 > len(z) {
			t.Fatalf("truncated offset at %d", i)
		}
		off := int(z[i]) | int(z[i+1])<<8
		i += 2
		m := int(tok&0xf) + 4
		if tok&0xf == 15 {
			for {
				x := z[i]
				i++
				m += int(x)
				if x != 255 {
					break
				}
			}
		}
		out = append(out, sequence{l, m, off})
	}
	return out
}

func optimalRoundtrip(t *testing.T, c *lz4block.CompressorOptimal, src []byte) ([]byte, []sequence) {
	t.Helper()
	dst := make([]byte, lz4block.CompressBlockBound(len(src)))
	n, err := c.CompressBlock(src, dst)
	if err != nil {
		t.Fatalf("CompressBlock(%d bytes): %v", len(src), err)
	}
	if n <= 0 {
		t.Fatalf("CompressBlock returned %d for %d input bytes", n, len(src))
	}
	z := dst[:n]
	dec := make([]byte, len(src))
	dn, err := lz4block.UncompressBlock(z, dec, nil)
	if err != nil {
		t.Fatalf("UncompressBlock: %v", err)
	}
	if dn != len(src) || !bytes.Equal(dec, src) {
		t.Fatalf("roundtrip mismatch: decoded %d of %d bytes", dn, len(src))
	}
	return z, parseSequences(t, z)
}

// TestOptimalExhaustive compares the optimal output length with an
// independent exhaustive encoder on short inputs.
func TestOptimalExhaustive(t *testing.T) {
	rng := rand.New(rand.NewSource(20261107))
	var c lz4block.CompressorOptimal
	for iter := 0; iter < 4000; iter++ {
		n := rng.Intn(19) // 0..18, spanning the 15-literal threshold
		src := make([]byte, n)
		switch iter % 6 {
		case 0, 1:
			alpha := 2 + rng.Intn(4)
			for i := range src {
				src[i] = byte('a' + rng.Intn(alpha))
			}
		case 2, 3:
			set := []byte{0, 1, 2, 253, 254, 255}
			for i := range src {
				src[i] = set[rng.Intn(len(set))]
			}
		default:
			rng.Read(src)
			if n > 0 && iter%7 == 0 {
				src[n/2] = 255
			}
		}
		want := oracleMinSize(src)
		z, _ := optimalRoundtrip(t, &c, src)
		if len(z) != want {
			t.Fatalf("n=%d src=% x: optimal %d bytes, exhaustive minimum %d", n, src, len(z), want)
		}
	}
}

// TestOptimalConstructed pins hand-built inputs where greedy longest-match
// parsing, length extension thresholds, offset-1 copies and end-of-block
// constraints matter.
func TestOptimalConstructed(t *testing.T) {
	var c lz4block.CompressorOptimal

	// A greedy parser taking the longest match at the first match position is
	// not optimal. After the common first match it takes, at position 15, a
	// 5-byte match with offset 3 and then 10 literals. The optimal parse
	// spends one literal there and starts an 8-byte match with offset 14 at
	// position 16, covering the bytes the greedy match blocked:
	//
	//	optimal: lit=7 m=8 off=6 ; lit=1 m=8 off=14 ; lit=6
	//	greedy:  lit=7 m=8 off=6 ; m=5 off=3         ; lit=10
	greedyWitness := []byte("bbbbababbbababbabbababbbbaaaaa")
	z, seqs := optimalRoundtrip(t, &c, greedyWitness)
	if len(z) != 21 {
		t.Fatalf("witness: got %d bytes, want 21", len(z))
	}
	wantSeqs := []sequence{{7, 8, 6}, {1, 8, 14}, {6, 0, 0}}
	if len(seqs) != len(wantSeqs) {
		t.Fatalf("witness: %d sequences, want %d: %v", len(seqs), len(wantSeqs), seqs)
	}
	for i, s := range wantSeqs {
		if seqs[i] != s {
			t.Fatalf("witness sequence %d: %+v, want %+v (all: %v)", i, seqs[i], s, seqs)
		}
	}
	// The greedy parsers, including HC at its deepest level, must be strictly
	// longer on this input.
	hc := (&lz4.CompressorHC{Level: lz4.Level9}).CompressBlock
	hcDst := make([]byte, lz4block.CompressBlockBound(len(greedyWitness)))
	nHC, err := hc(greedyWitness, hcDst)
	if err != nil {
		t.Fatal(err)
	}
	if nHC <= len(z) {
		t.Fatalf("level9 output %d is not longer than optimal %d", nHC, len(z))
	}

	// Offset-1 run: 30 equal bytes. The first match copies the previous byte
	// with offset 1 and leaves exactly five trailing literals.
	run := bytes.Repeat([]byte{'x'}, 30)
	_, seqs = optimalRoundtrip(t, &c, run)
	if seqs[0].offset != 1 || seqs[0].litLen != 1 {
		t.Fatalf("run: first sequence %+v, want offset 1, 1 literal", seqs[0])
	}
	if last := seqs[len(seqs)-1]; last.litLen != 5 || last.matchLen != 0 {
		t.Fatalf("run: final sequence %+v, want 5 literals", last)
	}

	// Smallest compressible input: 13 equal bytes, match start exactly 12
	// bytes before the end and five trailing literals.
	small := bytes.Repeat([]byte{'q'}, 13)
	z, seqs = optimalRoundtrip(t, &c, small)
	if len(z) != 10 {
		t.Fatalf("13 equal bytes: %d bytes, want 10", len(z))
	}
	if seqs[0] != (sequence{1, 7, 1}) {
		t.Fatalf("13 equal bytes: %+v, want {1 7 1}", seqs[0])
	}

	// A repeated 4-byte window appearing only 12 bytes in cannot be a match:
	// its start is past n-12, so the block stays literal only.
	late := make([]byte, 16)
	for i := 0; i < 12; i++ {
		late[i] = byte(i)
	}
	copy(late[12:], late[:4])
	z, seqs = optimalRoundtrip(t, &c, late)
	if len(z) != literalOnlySize(16) || len(seqs) != 1 {
		t.Fatalf("late repeat: %d bytes, %d sequences, want literal only %d", len(z), len(seqs), literalOnlySize(16))
	}

	// Empty input: one zero token, decodes to zero bytes.
	empty := []byte{}
	zdst := make([]byte, lz4block.CompressBlockBound(0))
	n, err := c.CompressBlock(empty, zdst)
	if err != nil || n != 1 || zdst[0] != 0 {
		t.Fatalf("empty: n=%d err=%v token=% x", n, err, zdst[:n])
	}
	if dn, err := lz4block.UncompressBlock(zdst[:n], make([]byte, 1), nil); err != nil || dn != 0 {
		t.Fatalf("empty decode: n=%d err=%v", dn, err)
	}

	// One to twelve bytes: always a single literal-only sequence.
	for n := 1; n <= 12; n++ {
		src := bytes.Repeat([]byte{'z'}, n)
		z, seqs = optimalRoundtrip(t, &c, src)
		if len(z) != literalOnlySize(n) || len(seqs) != 1 || seqs[0].litLen != n {
			t.Fatalf("n=%d: %d bytes seqs=%v, want literal only %d", n, len(z), seqs, literalOnlySize(n))
		}
	}
}

// lcgData returns deterministic high-entropy data, failing if it happens to
// contain a repeated 4-byte window (which would make it compressible).
func lcgData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	seen := map[uint32]bool{}
	for i := 0; i+4 <= n; i++ {
		w := uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		if seen[w] {
			t.Fatalf("LCG data has a repeated 4-byte window at %d", i)
		}
		seen[w] = true
	}
	return b
}

// TestOptimalThresholds checks the real extension costs around the literal
// (15, 270) and match (19) length thresholds.
func TestOptimalThresholds(t *testing.T) {
	var c lz4block.CompressorOptimal

	// Literal-only blocks: crossing a threshold adds one extension byte on
	// top of the extra literal byte.
	for _, tc := range []struct {
		n, size int
	}{
		{14, 15},
		{15, 17}, // token, zero extension byte, 15 literals
		{269, 271},
		{270, 273}, // the second extension byte appears here
	} {
		src := lcgData(t, tc.n)
		z, seqs := optimalRoundtrip(t, &c, src)
		if len(z) != tc.size {
			t.Fatalf("literal n=%d: %d bytes, want %d", tc.n, len(z), tc.size)
		}
		if len(seqs) != 1 || seqs[0].litLen != tc.n {
			t.Fatalf("literal n=%d: sequences %v", tc.n, seqs)
		}
	}

	// A 20-byte match needs one match extension byte (code 16). Stopping at
	// 18 costs no extension but forces two more literals, which is one byte
	// worse; the 19-byte tie (one extension byte versus one literal) is
	// resolved towards the shorter match. Four literals, twenty copied
	// bytes against offset 4, five forced trailing literals: 29 bytes.
	src := append(append([]byte("abcd"), bytes.Repeat([]byte("abcd"), 5)...), []byte("zzzzz")...)
	if len(src) != 29 {
		t.Fatal(len(src))
	}
	z, seqs := optimalRoundtrip(t, &c, src)
	found := false
	for _, s := range seqs {
		if s.matchLen == 20 && s.offset == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no 20-byte offset-4 match in %v", seqs)
	}
	// token + 4 literals + offset + extension + final 5 literals = 14.
	if len(z) != 14 {
		t.Fatalf("20-byte match block: %d bytes, want 14 (%v)", len(z), seqs)
	}
}

// TestOptimalLimits covers the input cap, buffer behavior and source safety.
func TestOptimalLimits(t *testing.T) {
	var c lz4block.CompressorOptimal

	if lz4block.OptimalMaxInputSize != 8<<10 {
		t.Fatalf("OptimalMaxInputSize = %d", lz4block.OptimalMaxInputSize)
	}
	if lz4block.OptimalMaxWorkspace < 0 {
		t.Fatal("bad workspace constant")
	}

	// Exactly 8KiB is accepted; one byte more is rejected before touching
	// the destination.
	max := bytes.Repeat([]byte{'z'}, lz4block.OptimalMaxInputSize)
	optimalRoundtrip(t, &c, max)
	tooLarge := make([]byte, lz4block.OptimalMaxInputSize+1)
	sentinel := byte(0xA5)
	dst := make([]byte, 16)
	for i := range dst {
		dst[i] = sentinel
	}
	n, err := c.CompressBlock(tooLarge, dst)
	if !errors.Is(err, lz4errors.ErrOptimalInputTooLarge) || n != 0 {
		t.Fatalf("too large: n=%d err=%v", n, err)
	}
	for i, b := range dst {
		if b != sentinel {
			t.Fatalf("dst modified at %d", i)
		}
	}

	// A short destination returns the recognizable error, both for
	// compressible and incompressible data; the exact size fits.
	compressible := bytes.Repeat([]byte("abcdefgh"), 64) // 512 bytes
	full := make([]byte, lz4block.CompressBlockBound(len(compressible)))
	need, err := c.CompressBlock(compressible, full)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := c.CompressBlock(compressible, full[:need-1]); !errors.Is(err, lz4errors.ErrOptimalShortBuffer) || n != 0 {
		t.Fatalf("short dst compressible: n=%d err=%v", n, err)
	}
	if n, err := c.CompressBlock(compressible, full[:need]); err != nil || n != need {
		t.Fatalf("exact dst: n=%d err=%v", n, err)
	}

	incompressible := lcgData(t, 200)
	want := literalOnlySize(200)
	ib := make([]byte, lz4block.CompressBlockBound(200))
	if n, err := c.CompressBlock(incompressible, ib[:want]); err != nil || n != want {
		t.Fatalf("incompressible exact dst: n=%d err=%v, want %d", n, err, want)
	}
	if n, err := c.CompressBlock(incompressible, ib[:want-1]); !errors.Is(err, lz4errors.ErrOptimalShortBuffer) || n != 0 {
		t.Fatalf("short dst incompressible: n=%d err=%v", n, err)
	}
	// Incompressible data decodes from the full literal encoding.
	if dn, err := lz4block.UncompressBlock(ib[:want], make([]byte, 200), nil); err != nil || dn != 200 {
		t.Fatalf("incompressible decode: n=%d err=%v", dn, err)
	}

	// A larger capacity than length must not allow writes past len.
	tight := make([]byte, need-1, need+32)
	if _, err := c.CompressBlock(compressible, tight); !errors.Is(err, lz4errors.ErrOptimalShortBuffer) {
		t.Fatalf("tight cap: err=%v", err)
	}

	// The source is never modified, including overlapping offset-1 matches.
	for _, src := range [][]byte{bytes.Repeat([]byte{'m'}, 4096), append([]byte("abab"), lcgData(t, 96)...)} {
		orig := append([]byte(nil), src...)
		d := make([]byte, lz4block.CompressBlockBound(len(src)))
		if _, err := c.CompressBlock(src, d); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(src, orig) {
			t.Fatal("source modified")
		}
	}
}

// TestOptimalDeterministic checks stable output across fresh, reused and
// Reset compressors.
func TestOptimalDeterministic(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("bbbbababbbababbabbababbbbaaaaa"),
		bytes.Repeat([]byte{'z'}, 8192),
		lcgData(t, 500),
	}
	encode := func(c *lz4block.CompressorOptimal, src []byte) []byte {
		dst := make([]byte, lz4block.CompressBlockBound(len(src)))
		n, err := c.CompressBlock(src, dst)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), dst[:n]...)
	}
	var c lz4block.CompressorOptimal
	for _, src := range inputs {
		ref := encode(&c, src)
		for i := 0; i < 3; i++ {
			if got := encode(&c, src); !bytes.Equal(got, ref) {
				t.Fatalf("n=%d reuse %d differs", len(src), i)
			}
		}
		c.Reset()
		if got := encode(&c, src); !bytes.Equal(got, ref) {
			t.Fatalf("n=%d post-Reset differs", len(src))
		}
		var fresh lz4block.CompressorOptimal
		if got := encode(&fresh, src); !bytes.Equal(got, ref) {
			t.Fatalf("n=%d fresh instance differs", len(src))
		}
		dst := make([]byte, lz4block.CompressBlockBound(len(src)))
		n, err := lz4block.CompressBlockOptimal(src, dst)
		if err != nil || !bytes.Equal(dst[:n], ref) {
			t.Fatalf("n=%d pooled: n=%d err=%v", len(src), n, err)
		}
	}
}

// TestOptimalMedium checks repetitive and high-entropy 8KiB inputs for the
// O(n^2) time bound, exact roundtrip and dominance over the greedy levels.
func TestOptimalMedium(t *testing.T) {
	patterns := []struct {
		name string
		src  []byte
	}{
		{"run", bytes.Repeat([]byte{'z'}, 8192)},
		{"periodic", repeating("abcd", 8192)},
		{"textish", repeating("the quick brown fox jumps over the lazy dog; ", 8192)},
		{"random", lcgData(t, 8192)},
		{"mixed", append(repeating("abcdefgh", 4096), lcgData(t, 4096)...)},
	}

	var c lz4block.CompressorOptimal
	for _, tc := range patterns {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dst := make([]byte, lz4block.CompressBlockBound(len(tc.src)))
			start := time.Now()
			n, err := c.CompressBlock(tc.src, dst)
			if elapsed := time.Since(start); err == nil && elapsed > 10*time.Second {
				t.Fatalf("compression took %v", elapsed)
			}
			if err != nil {
				t.Fatal(err)
			}
			dec := make([]byte, len(tc.src))
			dn, err := lz4block.UncompressBlock(dst[:n], dec, nil)
			if err != nil || dn != len(tc.src) || !bytes.Equal(dec, tc.src) {
				t.Fatalf("roundtrip: dn=%d err=%v", dn, err)
			}
			if n > lz4block.CompressBlockBound(len(tc.src)) {
				t.Fatalf("output %d exceeds bound", n)
			}

			// Optimal must never be longer than the greedy compressors.
			for _, comp := range []struct {
				name string
				fn   func([]byte, []byte) (int, error)
			}{
				{"fast", lz4block.CompressBlock},
				{"ccompat", lz4block.CompressBlockCCompat},
				{"hc9", func(src, d []byte) (int, error) {
					return lz4block.CompressBlockHC(src, d, lz4block.CompressionLevel(lz4.Level9))
				}},
			} {
				ref := make([]byte, lz4block.CompressBlockBound(len(tc.src)))
				m, _ := comp.fn(tc.src, ref)
				if m != 0 && m < n {
					t.Fatalf("%s compressed to %d, optimal to %d", comp.name, m, n)
				}
			}
		})
	}
}

func repeating(pattern string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = pattern[i%len(pattern)]
	}
	return b
}
