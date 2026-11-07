package lz4block

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"runtime"
	"runtime/debug"
	"testing"
)

// refSeq is one sequence parsed from a raw block by refParseBlock.
type refSeq struct {
	lit   []byte
	off   int
	mLen  int // 0 for the final, literals-only sequence
	isEnd bool
}

// refParseBlock is a test-local, deliberately independent block parser. It
// follows the format specification (the final token's match nibble is
// ignored) and shares no code with parseBlock.
func refParseBlock(t *testing.T, src []byte) ([]refSeq, uint64) {
	t.Helper()
	seqs, size, ok := refTryParse(src)
	if !ok {
		t.Fatalf("refParseBlock: invalid block % x", src)
	}
	return seqs, size
}

// refTryParse is the strict end rule used by the tests' reference parser:
// every block must end with a literals-only final sequence exactly at its
// last byte (a block ending right after a match, which the package decoder
// leniently accepts, is rejected).
func refTryParse(src []byte) ([]refSeq, uint64, bool) {
	if len(src) == 0 {
		return nil, 0, false
	}
	var seqs []refSeq
	si := 0
	var di uint64
	for {
		if si >= len(src) {
			return nil, 0, false
		}
		tok := src[si]
		si++
		litLen := int(tok >> 4)
		if litLen == 0xF {
			for {
				if si >= len(src) {
					return nil, 0, false
				}
				x := src[si]
				si++
				litLen += int(x)
				if x != 0xFF {
					break
				}
			}
		}
		if litLen < 0 || si+litLen > len(src) {
			return nil, 0, false
		}
		lit := src[si : si+litLen]
		si += litLen
		di += uint64(litLen)

		if si == len(src) {
			seqs = append(seqs, refSeq{lit: lit, isEnd: true})
			return seqs, di, true
		}
		if si+2 > len(src) {
			return nil, 0, false
		}
		off := int(binary.LittleEndian.Uint16(src[si:]))
		si += 2
		if off == 0 || uint64(off) > di {
			return nil, 0, false
		}
		mLen := int(tok&0x0F) + minMatch
		if tok&0x0F == 0x0F {
			for {
				if si >= len(src) {
					return nil, 0, false
				}
				x := src[si]
				si++
				mLen += int(x)
				if mLen < 0 {
					return nil, 0, false
				}
				if x != 0xFF {
					break
				}
			}
		}
		di += uint64(mLen)
		seqs = append(seqs, refSeq{lit: lit, off: off, mLen: mLen})
	}
}

// matchRef is one existing match identified by offset and length.
type matchRef struct{ off, mLen int }

func matchRefs(seqs []refSeq) []matchRef {
	var refs []matchRef
	for _, s := range seqs {
		if !s.isEnd {
			refs = append(refs, matchRef{s.off, s.mLen})
		}
	}
	return refs
}

// mustCompressBlock compresses src with the fast compressor or stores it as a
// single literal-only sequence when it is not compressible, so callers can
// pass arbitrary data.
func mustCompressBlock(t *testing.T, src []byte) []byte {
	t.Helper()
	buf := make([]byte, CompressBlockBound(len(src)))
	n, err := CompressBlock(src, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return appendSeq(nil, src, 0, 0)
	}
	return buf[:n]
}

// checkJoin joins lblock and rblock and verifies, with both decoders, that the
// result expands to want. It also parses the result and checks that every
// match from both inputs survives with its original offset and length.
func checkJoin(t *testing.T, lblock, rblock []byte, want []byte, maxSize int) []byte {
	t.Helper()
	joined, err := JoinBlocks(lblock, rblock, maxSize)
	if err != nil {
		t.Fatalf("JoinBlocks: %v", err)
	}

	lSeqs, lSize := refParseBlock(t, lblock)
	rSeqs, rSize := refParseBlock(t, rblock)
	jSeqs, jSize := refParseBlock(t, joined)
	if jSize != uint64(len(want)) || lSize+rSize != jSize {
		t.Fatalf("sizes: joined=%d left=%d right=%d want=%d", jSize, lSize, rSize, len(want))
	}

	// Every old match must still be there, in order, untouched.
	wantRefs := append(matchRefs(lSeqs), matchRefs(rSeqs)...)
	gotRefs := matchRefs(jSeqs)
	if len(gotRefs) != len(wantRefs) {
		t.Fatalf("matches: got %d, want %d", len(gotRefs), len(wantRefs))
	}
	for i := range wantRefs {
		if gotRefs[i] != wantRefs[i] {
			t.Fatalf("match %d changed: got %+v want %+v", i, gotRefs[i], wantRefs[i])
		}
	}

	// The final token must carry a normalized zero match nibble.
	lastLit := jSeqs[len(jSeqs)-1].lit
	finalTok := len(joined) - len(lastLit) - lenExtStart(lastLit)
	if joined[finalTok]&0x0F != 0 {
		t.Fatalf("final token match nibble not normalized: %x", joined)
	}

	// Independent decoder verification, both the portable and the assembly
	// decoder, into an exactly sized guarded destination.
	for _, d := range testDecoders {
		got, n := guardedDecode(t, d.fn, joined, nil, len(want))
		if n != len(want) || !bytes.Equal(got, want) {
			t.Fatalf("%s: decoded %d bytes, want %d", d.name, n, len(want))
		}
	}
	n, err := UncompressBlock(joined, make([]byte, len(want)), nil)
	if err != nil || n != len(want) {
		t.Fatalf("UncompressBlock: n=%d err=%v", n, err)
	}
	return joined
}

// lenExtStart returns the size of the token and literal-length extension of
// a literal-only sequence with the given literals.
func lenExtStart(lit []byte) int {
	if len(lit) < 0xF {
		return 1
	}
	return 1 + lenExtSize(len(lit))
}

func TestJoinBlocksBasic(t *testing.T) {
	type tc struct {
		name       string
		lplain     []byte
		rplain     []byte
		lblock     []byte
		rblock     []byte
		maxSize    int
		wantJoined []byte // expected exact output where trivial
	}
	empty := []byte{0} // legal encoding of empty data.

	cases := []tc{
		{
			name:       "both empty",
			lblock:     empty,
			rblock:     empty,
			maxSize:    0,
			wantJoined: empty,
		},
		{
			name:    "left empty",
			lplain:  nil,
			rplain:  []byte("hello"),
			lblock:  empty,
			rblock:  appendSeq(nil, []byte("hello"), 0, 0),
			maxSize: 64,
		},
		{
			name:    "right empty",
			lplain:  []byte("hello"),
			rplain:  nil,
			lblock:  appendSeq(nil, []byte("hello"), 0, 0),
			rblock:  empty,
			maxSize: 64,
		},
		{
			name:    "both literals only",
			lplain:  []byte("left-literals"),
			rplain:  []byte("right-literals"),
			lblock:  appendSeq(nil, []byte("left-literals"), 0, 0),
			rblock:  appendSeq(nil, []byte("right-literals"), 0, 0),
			maxSize: 64,
		},
		{
			name:    "right first sequence has a match",
			lplain:  []byte("L"),
			rplain:  []byte("abcabcatail"),
			lblock:  appendSeq(nil, []byte("L"), 0, 0),
			rblock:  appendSeq(appendSeq(nil, []byte("abc"), 3, 4), []byte("tail"), 0, 0),
			maxSize: 64,
		},
		{
			name:    "both sides have matches",
			lplain:  []byte("abcabcaX"),
			rplain:  []byte("xyzxyzx!"),
			lblock:  appendSeq(appendSeq(nil, []byte("abc"), 3, 4), []byte("X"), 0, 0),
			rblock:  appendSeq(appendSeq(nil, []byte("xyz"), 3, 4), []byte("!"), 0, 0),
			maxSize: 64,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := append(append([]byte{}, c.lplain...), c.rplain...)
			joined := checkJoin(t, c.lblock, c.rblock, want, c.maxSize)
			if c.wantJoined != nil && !bytes.Equal(joined, c.wantJoined) {
				t.Fatalf("joined=% x want % x", joined, c.wantJoined)
			}
		})
	}
}

func TestJoinBlocksLiteralThresholds(t *testing.T) {
	// Merged literal lengths around the 15 token threshold and the 270 byte
	// threshold where a second extension byte is needed.
	pairs := []struct{ l, r int }{
		{0, 0}, {14, 1}, {15, 0}, {14, 2}, {1, 14},
		{200, 69}, // 269: one extension byte
		{200, 70}, // 270: two extension bytes
		{200, 71}, // 271
		{300, 300},
	}
	for _, p := range pairs {
		name := fmt.Sprintf("%d+%d", p.l, p.r)
		t.Run(name, func(t *testing.T) {
			lplain := testPattern(p.l, 0x11)
			rplain := testPattern(p.r, 0x22)
			lblock := appendSeq(nil, lplain, 0, 0)
			rblock := appendSeq(nil, rplain, 0, 0)
			want := append(append([]byte{}, lplain...), rplain...)
			joined := checkJoin(t, lblock, rblock, want, math.MaxInt)

			// The merged length extension must be encoded for the true total.
			seqs, _ := refParseBlock(t, joined)
			if len(seqs) != 1 || len(seqs[0].lit) != p.l+p.r {
				t.Fatalf("expected one literal-only sequence of %d bytes", p.l+p.r)
			}
			wantExt := lenExtSize(p.l + p.r)
			if got := len(joined) - 1 - (p.l + p.r); got != wantExt {
				t.Fatalf("extension bytes: got %d want %d (total %d)", got, wantExt, p.l+p.r)
			}
		})
	}
}

func TestJoinBlocksLongOffset(t *testing.T) {
	// A 16-bit offset at its maximum, resolved entirely inside the right block.
	lits := testPattern(65535, 0x77)
	rblock := appendSeq(appendSeq(nil, lits, 65535, 4), []byte("end.."), 0, 0)
	rplain := append(append([]byte{}, lits...), lits[:4]...)
	rplain = append(rplain, []byte("end..")...)
	lblock := appendSeq(nil, []byte("L"), 0, 0)
	want := append([]byte("L"), rplain...)
	joined := checkJoin(t, lblock, rblock, want, math.MaxInt)

	seqs, _ := refParseBlock(t, joined)
	var found bool
	for _, s := range seqs {
		if s.off == 65535 && s.mLen == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("long offset match missing from % x", joined[:16])
	}
}

func TestJoinBlocksRejects(t *testing.T) {
	good := appendSeq(appendSeq(nil, []byte("abc"), 3, 4), []byte("tail"), 0, 0)
	bigLeft := appendSeq(nil, testPattern(100, 1), 0, 0)

	mustFail := func(name string, left, right []byte, maxSize int) {
		t.Helper()
		if _, err := JoinBlocks(left, right, maxSize); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}

	mustFail("empty left slice", nil, good, math.MaxInt)
	mustFail("empty left slice empty", []byte{}, good, math.MaxInt)
	mustFail("empty right slice", good, nil, math.MaxInt)
	mustFail("negative max size", good, good, -1)
	mustFail("max size zero with data", good, good, 0)

	// Right offset reaches outside right's own data: it would need a
	// dictionary, and a big left block must not make it acceptable.
	needsDict := appendSeq(appendSeq(nil, []byte("abc"), 4, 4), []byte("tail"), 0, 0)
	mustFail("right needs dictionary", bigLeft, needsDict, math.MaxInt)
	mustFail("zero offset", bigLeft,
		appendSeq(appendSeq(nil, []byte("abc"), 0, 4), []byte("tail"), 0, 0), math.MaxInt)
	// Same violation in a later match, after a legal first one: the joined
	// output would place enough left data in reach, but right on its own has
	// only 7 bytes generated when it asks for offset 100.
	laterOOB := appendSeq(nil, []byte("abc"), 3, 4)
	laterOOB = appendSeq(laterOOB, nil, 100, 4)
	laterOOB = appendSeq(laterOOB, []byte("tail"), 0, 0)
	mustFail("right later match out of bounds", bigLeft, laterOOB, math.MaxInt)

	// Each block (11 bytes) fits the bound on its own, but their sum does
	// not: the total is checked while parsing, before allocation.
	mustFail("max size exceeded by sum", good, good, 15)

	// Every proper prefix of a multi-sequence block is classified by the
	// strict end rule: truncated prefixes are rejected explicitly rather than
	// via an out-of-bounds write, and a prefix that is itself a complete
	// literals-only block is accepted. The prefix ending right after the
	// match (no final sequence) is rejected even though the package decoder
	// leniently accepts it.
	if _, _, ok := refTryParse(good[:6]); ok {
		t.Fatal("reference: block ending after a match must be invalid")
	}
	goodPlain := make([]byte, 256)
	gn := decodeBlockGo(goodPlain, good, nil)
	if gn < 0 {
		t.Fatal("good block does not decode")
	}
	goodPlain = goodPlain[:gn]
	for i := 0; i < len(good); i++ {
		p := good[:i]
		if _, _, ok := refTryParse(p); !ok {
			mustFail(fmt.Sprintf("left prefix %d", i), p, good, math.MaxInt)
			mustFail(fmt.Sprintf("right prefix %d", i), good, p, math.MaxInt)
			continue
		}
		prefixPlain := make([]byte, 256)
		pn := decodeBlockGo(prefixPlain, p, nil)
		if pn < 0 {
			t.Fatalf("strict-valid prefix %d does not decode", i)
		}
		checkJoin(t, p, good, append(prefixPlain[:pn], goodPlain...), math.MaxInt)
		checkJoin(t, good, p, append(goodPlain, prefixPlain[:pn]...), math.MaxInt)
	}

	// Trailing bytes after a complete final sequence.
	mustFail("trailing byte", []byte{0x00, 0x10}, emptyBlock(), math.MaxInt)
	mustFail("trailing byte right", emptyBlock(), []byte{0x00, 0x10}, math.MaxInt)

	// A literal extension that promises more literals than the block holds.
	mustFail("bad literal extension", emptyBlock(), []byte{0xF0, 0x10, 'a'}, math.MaxInt)
	// A truncated offset and a truncated match extension.
	mustFail("truncated offset", emptyBlock(), []byte{0x10, 'a', 0x01}, math.MaxInt)
	mustFail("truncated match ext", emptyBlock(), []byte{0x1F, 'a', 0x01, 0x00, 0xFF}, math.MaxInt)
}

func emptyBlock() []byte { return []byte{0x00} }

func TestJoinBlocksFinalNibbleIgnored(t *testing.T) {
	// Per the format, the final token's match nibble is ignored. These blocks
	// carry a stray 0xF there; JoinBlocks must accept them and normalize.
	lit := []byte{0x1F, 'x'} // one literal, stray match nibble
	want := []byte("xx")
	joined := checkJoin(t, lit, lit, want, math.MaxInt)
	if joined[0] != 0x20 {
		t.Fatalf("normalized token = %#x, want 0x20", joined[0])
	}

	// Same on the left of a right block whose first sequence has a match.
	r := appendSeq(appendSeq(nil, []byte("abc"), 3, 4), []byte("tail"), 0, 0)
	want = append([]byte("x"), []byte("abcabcatail")...)
	checkJoin(t, lit, r, want, math.MaxInt)
}

// bombBlock encodes one literal byte fill followed by an overlapping match
// (offset 1) that expands to total bytes, then an empty final sequence. The
// compressed size is about total/255 bytes.
func bombBlock(fill byte, total int) []byte {
	b := []byte{0x1F, fill, 0x01, 0x00}
	v := total - 1 - minMatch - 0xF // match extension value
	for ; v >= 0xFF; v -= 0xFF {
		b = append(b, 0xFF)
	}
	b = append(b, byte(v), 0x00)
	return b
}

func TestJoinBlocksHugeExpansionSmallInput(t *testing.T) {
	const total = 1 << 30 // 1 GiB claimed decompressed size
	rblock := bombBlock('A', total)
	if len(rblock) > total/200 {
		t.Fatalf("bomb block not small: %d bytes", len(rblock))
	}

	// The bound is enforced by parsing before the output is published.
	if _, err := JoinBlocks([]byte{0}, rblock, total-1); err == nil {
		t.Fatal("expected error when the merged size exceeds the bound")
	}

	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	joined, err := JoinBlocks([]byte{0}, rblock, total)
	runtime.ReadMemStats(&m1)
	if err != nil {
		t.Fatal(err)
	}
	// A join proportional to the decompressed size would allocate ~1 GiB.
	if d := m1.TotalAlloc - m0.TotalAlloc; d > 64<<20 {
		t.Fatalf("allocated %d bytes joining a block of %d decompressed bytes", d, total)
	}
	if len(joined) != len(rblock) {
		t.Fatalf("joined size %d, want %d (only the boundary token is rewritten)", len(joined), len(rblock))
	}
	seqs, size := refParseBlock(t, joined)
	if size != total {
		t.Fatalf("parsed decompressed size %d, want %d", size, total)
	}
	if refs := matchRefs(seqs); len(refs) != 1 || refs[0] != (matchRef{1, total - 1}) {
		t.Fatalf("old match not preserved: %+v", refs)
	}

	// Positive decoder evidence for the same shape at a decodable scale, with
	// a non-empty left block so the boundary merge is exercised too: right
	// expands to small 'A' bytes, and the joined plaintext is "hello"
	// followed by small 'A's.
	const small = 1 << 20
	lblock := appendSeq(nil, []byte("hello"), 0, 0)
	checkJoin(t, lblock, bombBlock('A', small),
		append([]byte("hello"), bytes.Repeat([]byte("A"), small)...), math.MaxInt)
}

func TestJoinBlocksNoAliasing(t *testing.T) {
	lplain := bytes.Repeat([]byte("left-text-"), 100)
	rplain := bytes.Repeat([]byte("right-text-"), 100)
	lblock := mustCompressBlock(t, lplain)
	rblock := mustCompressBlock(t, rplain)
	want := append(append([]byte{}, lplain...), rplain...)

	joined, err := JoinBlocks(lblock, rblock, math.MaxInt)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the inputs after the call must not affect the result.
	for i := range lblock {
		lblock[i] = 0
	}
	for i := range rblock {
		rblock[i] = 0
	}
	out := make([]byte, len(want))
	n, err := UncompressBlock(joined, out, nil)
	if err != nil || n != len(want) || !bytes.Equal(out, want) {
		t.Fatalf("decode after input mutation: n=%d err=%v", n, err)
	}
}

func TestJoinBlocksRandomized(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	pools := [][]byte{
		bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 3000),
		bytes.Repeat([]byte{'A'}, 70000),
	}
	for _, data := range pools {
		cuts := []int{0, 1, 5, 13, 14, 15, 16, 17, 255, 256, 257, len(data) / 2, len(data) - 1}
		for _, cut := range cuts {
			lplain, rplain := data[:cut], data[cut:]
			lblock := mustCompressBlock(t, lplain)
			rblock := mustCompressBlock(t, rplain)
			want := append(append([]byte{}, lplain...), rplain...)
			checkJoin(t, lblock, rblock, want, math.MaxInt)
		}
	}
	// Incompressible halves fall back to literal-only blocks.
	random := make([]byte, 20000)
	rnd.Read(random)
	for _, cut := range []int{0, 1, 100, 9999, 10000} {
		lblock := mustCompressBlock(t, random[:cut])
		rblock := mustCompressBlock(t, random[cut:])
		checkJoin(t, lblock, rblock, random, math.MaxInt)
	}
}
