package lz4_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"

	"github.com/pierrec/lz4/v4"
)

// The tests in this file exercise LimitedReader and its Limits on hostile
// streams: limits hit exactly and by one byte, counters that accumulate over
// concatenated frames, zero-output sequences that must not bypass limits,
// untrusted size fields, short writes, and accounting that reflects bytes
// decoded rather than bytes handed back.

// countingReader records every Read call: how many, how many bytes were
// actually delivered, and whether requests stayed within an expected cap.
type countingReader struct {
	data     []byte
	pos      int
	reads    int
	bytes    int
	maxReq   int
	expect   uint64 // if nonzero, every request must fit in expect - bytes so far
	violated int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	if len(p) > c.maxReq {
		c.maxReq = len(p)
	}
	if c.expect != 0 && uint64(len(p)) > c.expect-uint64(c.bytes) {
		c.violated++
	}
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := len(p)
	if n > len(c.data)-c.pos {
		n = len(c.data) - c.pos
	}
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	c.bytes += n
	return n, nil
}

var limitedModes = []decodeMode{
	{"Read/small", 1, 7},
	{"Read/direct", 1, 4<<20 + 1},
	{"Read/conc", 4, 7},
	{"WriteTo", 1, 0},
	{"WriteTo/conc", 4, 0},
}

// runLimited decodes in through one of the modes and returns the output,
// usage, source read counts and error.
func runLimited(t *testing.T, in []byte, lim lz4.Limits, m decodeMode) ([]byte, lz4.LimitUsage, *countingReader, error) {
	t.Helper()
	cr := &countingReader{data: in}
	zr := lz4.NewLimitedReader(cr, lim)
	if err := zr.Apply(lz4.ConcurrencyOption(m.conc)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var err error
	if m.bufSize == 0 {
		_, err = zr.WriteTo(&out)
	} else {
		buf := make([]byte, m.bufSize)
		for stalls := 0; stalls < 100000; {
			var n int
			n, err = zr.Read(buf)
			out.Write(buf[:n])
			if err != nil {
				break
			}
			if n == 0 {
				stalls++
			} else {
				stalls = 0
			}
		}
		if err == nil {
			t.Fatalf("decoder stalled without ending: %d bytes", out.Len())
		}
		if errors.Is(err, io.EOF) {
			err = nil
		}
	}
	return out.Bytes(), zr.Usage(), cr, err
}

func asLimitError(t *testing.T, err error) *lz4.LimitError {
	t.Helper()
	var le *lz4.LimitError
	if !errors.As(err, &le) {
		t.Fatalf("got %v, want a *lz4.LimitError", err)
	}
	if !errors.Is(err, lz4.ErrLimitExceeded) {
		t.Fatalf("%v does not wrap lz4.ErrLimitExceeded", le)
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("a limit error must not be io.EOF")
	}
	return le
}

// assertStickyNoRead checks that after a failure the reader keeps failing
// and never touches the source again.
func assertStickyNoRead(t *testing.T, zr *lz4.LimitedReader, cr *countingReader) {
	t.Helper()
	reads := cr.reads
	buf := make([]byte, 16)
	for range 3 {
		if _, err := zr.Read(buf); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("Read after limit failure returned %v", err)
		}
	}
	if cr.reads != reads {
		t.Fatalf("source was read %d time(s) after the failure", cr.reads-reads)
	}
}

// runSticky runs in and additionally checks error stickiness; only call for
// cases that fail. It reconstructs the reader since runLimited does not
// return it, so it keeps cr.
func runSticky(t *testing.T, in []byte, lim lz4.Limits, m decodeMode) (lz4.LimitUsage, *lz4.LimitError) {
	t.Helper()
	cr := &countingReader{data: in}
	zr := lz4.NewLimitedReader(cr, lim)
	if err := zr.Apply(lz4.ConcurrencyOption(m.conc)); err != nil {
		t.Fatal(err)
	}
	var err error
	if m.bufSize == 0 {
		_, err = zr.WriteTo(io.Discard)
	} else {
		buf := make([]byte, m.bufSize)
		for {
			n, rerr := zr.Read(buf)
			if rerr != nil {
				err = rerr
				break
			}
			_ = n
		}
	}
	le := asLimitError(t, err)
	usage := zr.Usage()
	assertStickyNoRead(t, zr, cr)
	return usage, le
}

func limOn(v uint64) lz4.Limit { return lz4.Limit{On: true, Value: v} }

func TestLimitedReaderExactAndOver(t *testing.T) {
	const (
		F       = flgV1 | flgIndep
		block10 = 10
	)
	ten := []byte("0123456789")
	hdr := cat(magic, desc(F, bd64K))
	oneBlock := cat(hdr, rawBlock(ten), endMark)
	twoBlocks := cat(hdr, rawBlock(ten[:5]), rawBlock(ten[5:]), endMark)
	twoFrames := cat(oneBlock, oneBlock)
	hdr4M := cat(magic, desc(F, 7<<4))
	emptyFrame := cat(hdr, endMark)

	type tc struct {
		name   string
		in     []byte
		lim    lz4.Limits
		ok     bool
		kind   lz4.LimitKind
		count  uint64
		outLen int // expected output prefix on failure, full length on success
		usage  func(lz4.LimitUsage)
		sync   bool // source-byte exactness only holds without readahead
	}
	cases := []tc{
		{
			name: "output/exact", in: oneBlock, outLen: 10, ok: true,
			lim: lz4.Limits{OutputBytes: limOn(10)},
		},
		{
			name: "output/overOne", in: oneBlock, outLen: 0, ok: false,
			kind: lz4.LimitOutputBytes, count: 10,
			lim: lz4.Limits{OutputBytes: limOn(9)},
		},
		{
			name: "output/zeroBlocksOnly", in: emptyFrame, outLen: 0, ok: true,
			lim: lz4.Limits{OutputBytes: limOn(0)},
		},
		{
			name: "output/zeroForbidsBytes", in: oneBlock, outLen: 0, ok: false,
			kind: lz4.LimitOutputBytes, count: 10,
			lim: lz4.Limits{OutputBytes: limOn(0)},
		},
		{
			name: "blocks/twoExact", in: twoBlocks, outLen: 10, ok: true,
			lim: lz4.Limits{Blocks: limOn(2)},
		},
		{
			name: "blocks/overOne", in: twoBlocks, outLen: 5, ok: false,
			kind: lz4.LimitBlocks, count: 2,
			lim: lz4.Limits{Blocks: limOn(1)},
		},
		{
			name: "blocks/zeroAllowsEmptyFrame", in: emptyFrame, outLen: 0, ok: true,
			lim: lz4.Limits{Blocks: limOn(0)},
		},
		{
			name: "blocks/zeroForbidsBlock", in: oneBlock, outLen: 0, ok: false,
			kind: lz4.LimitBlocks, count: 1,
			lim: lz4.Limits{Blocks: limOn(0)},
		},
		{
			name: "frames/exact", in: oneBlock, outLen: 10, ok: true,
			lim: lz4.Limits{Frames: limOn(1)},
		},
		{
			name: "frames/twoOverOne", in: twoFrames, outLen: 10, ok: false,
			kind: lz4.LimitFrames, count: 2,
			lim: lz4.Limits{Frames: limOn(1)},
		},
		{
			name: "frames/zero", in: oneBlock, outLen: 0, ok: false,
			kind: lz4.LimitFrames, count: 1,
			lim: lz4.Limits{Frames: limOn(0)},
		},
		{
			name: "blockSize/allowed", in: oneBlock, outLen: 10, ok: true,
			lim: lz4.Limits{BlockMaxSize: limOn(uint64(lz4.Block64Kb))},
		},
		{
			name: "blockSize/rejected4MiB", in: cat(hdr4M, endMark), outLen: 0, ok: false,
			kind: lz4.LimitBlockSize, count: uint64(lz4.Block4Mb),
			lim: lz4.Limits{BlockMaxSize: limOn(uint64(lz4.Block64Kb) - 1)},
		},
		{
			name: "source/exact", in: oneBlock, outLen: 10, ok: true, sync: true,
			lim: lz4.Limits{SourceBytes: limOn(uint64(len(oneBlock)))},
		},
		{
			// The budget runs out at the block size field, before any data
			// block is pulled: no output and exactly 7 source bytes read.
			name: "source/overOne", in: oneBlock, outLen: 0, ok: false, sync: true,
			kind: lz4.LimitSourceBytes, count: 8,
			lim: lz4.Limits{SourceBytes: limOn(7)},
		},
	}
	for _, c := range cases {
		modes := limitedModes
		if c.sync {
			modes = modes[:1] // Read/small, concurrency 1
		}
		for _, m := range modes {
			t.Run(fmt.Sprintf("%s/%s", c.name, m.name), func(t *testing.T) {
				out, usage, cr, err := runLimited(t, c.in, c.lim, m)
				if c.ok {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if len(out) != c.outLen {
						t.Fatalf("got %d output bytes, want %d", len(out), c.outLen)
					}
					if want := bytes.Repeat(ten, c.outLen/len(ten)+1)[:c.outLen]; !bytes.Equal(out, want) {
						t.Fatalf("bad output %q", out)
					}
					return
				}
				le := asLimitError(t, err)
				if bound := limitFor(c.lim, c.kind); le.Kind != c.kind || le.Limit != bound || le.Count != c.count {
					t.Fatalf("got kind=%s limit=%d count=%d, want kind=%s limit=%d count=%d",
						le.Kind, le.Limit, le.Count, c.kind, bound, c.count)
				}
				if len(out) != c.outLen {
					t.Fatalf("got %d output bytes before failure, want %d", len(out), c.outLen)
				}
				// After a failure the source must not move further.
				switch c.kind {
				case lz4.LimitBlockSize:
					// Rejected at the 7-byte descriptor, before blocks.
					if cr.bytes != 7 {
						t.Fatalf("read %d source bytes, want 7", cr.bytes)
					}
				case lz4.LimitFrames:
					if cr.bytes < 4 {
						t.Fatalf("frame magic not read: %d bytes", cr.bytes)
					}
				case lz4.LimitSourceBytes:
					if uint64(cr.bytes) != c.lim.SourceBytes.Value {
						t.Fatalf("read %d bytes, want exactly the budget %d", cr.bytes, c.lim.SourceBytes.Value)
					}
				}
				_ = usage
			})
		}
	}

	// Stickiness needs the reader itself, so run each failing kind once more.
	for _, c := range cases {
		if c.ok {
			continue
		}
		t.Run("sticky/"+c.name, func(t *testing.T) {
			if _, le := runSticky(t, c.in, c.lim, limitedModes[0]); le.Kind != c.kind {
				t.Fatalf("got %s, want %s", le.Kind, c.kind)
			}
		})
	}
}

// limitFor returns the configured bound for a kind; test helper.
func limitFor(l lz4.Limits, k lz4.LimitKind) uint64 {
	switch k {
	case lz4.LimitSourceBytes:
		return l.SourceBytes.Value
	case lz4.LimitOutputBytes:
		return l.OutputBytes.Value
	case lz4.LimitFrames:
		return l.Frames.Value
	case lz4.LimitBlocks:
		return l.Blocks.Value
	case lz4.LimitBlockSize:
		return l.BlockMaxSize.Value
	}
	return 0
}

// Counters accumulate across concatenated frames and reset nowhere on a
// frame boundary.
func TestLimitedReaderCrossFrame(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	hdr := cat(magic, desc(F, bd64K))
	block := rawBlock([]byte("abcde"))
	frame := cat(hdr, block, endMark)
	stream := cat(frame, frame)

	for _, m := range limitedModes {
		t.Run(m.name, func(t *testing.T) {
			lim := lz4.Limits{
				OutputBytes: limOn(7),
				Frames:      limOn(2),
				Blocks:      limOn(2),
			}
			out, usage, _, err := runLimited(t, stream, lim, m)
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitOutputBytes || le.Count != 10 {
				t.Fatalf("got %s count=%d, want output count=10", le.Kind, le.Count)
			}
			if len(out) != 5 {
				t.Fatalf("first frame delivered %d bytes, want 5", len(out))
			}
			if usage.Frames != 2 || usage.Blocks != 2 {
				t.Fatalf("usage=%+v: want 2 frames and 2 blocks seen", usage)
			}
		})
	}

	// Skippable frames count as frames and source bytes, in any position.
	for _, pos := range []string{"before", "between", "after"} {
		t.Run("skippable/"+pos, func(t *testing.T) {
			skip := skippable(2, []byte("SKIP")) // 12 bytes
			var in []byte
			switch pos {
			case "before":
				in = cat(skip, frame)
			case "between":
				in = cat(frame, skip, frame)
			case "after":
				in = cat(frame, skip)
			}
			lim := lz4.Limits{
				Frames:      limOn(1),
				SourceBytes: limOn(uint64(len(in))),
			}
			out, _, _, err := runLimited(t, in, lim, limitedModes[0])
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitFrames || le.Count != 2 {
				t.Fatalf("got %s count=%d, want frames count=2", le.Kind, le.Count)
			}
			if pos == "before" && len(out) != 0 {
				t.Fatalf("output before first data frame: %q", out)
			}
			if pos == "after" && len(out) != 5 {
				t.Fatalf("data frame output lost: %q", out)
			}
		})
	}

	// Counters reset only on LimitedReader.Reset.
	cr := &countingReader{data: frame}
	zr := lz4.NewLimitedReader(cr, lz4.Limits{Frames: limOn(1), OutputBytes: limOn(5)})
	if _, err := io.Copy(io.Discard, zr); err != nil {
		t.Fatal(err)
	}
	if u := zr.Usage(); u.Frames != 1 || u.OutputBytes != 5 {
		t.Fatalf("usage before reset: %+v", u)
	}
	cr2 := &countingReader{data: frame}
	zr.Reset(cr2, true)
	if u := zr.Usage(); u.Frames != 0 || u.OutputBytes != 0 || u.SourceBytes != 0 || u.Blocks != 0 {
		t.Fatalf("counters not zeroed by Reset: %+v", u)
	}
	if _, err := io.Copy(io.Discard, zr); err != nil {
		t.Fatalf("after Reset: %v", err)
	}
}

// Endless zero-output sequences must be bounded by frames, blocks and source
// caps instead of looping until memory runs out.
func TestLimitedReaderEmptySequences(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	hdr := cat(magic, desc(F, bd64K))

	t.Run("emptyRawBlocks", func(t *testing.T) {
		in := hdr
		for range 1000 {
			in = cat(in, rawBlock(nil))
		}
		in = cat(in, endMark)
		for _, m := range limitedModes {
			lim := lz4.Limits{Blocks: limOn(10), SourceBytes: limOn(uint64(len(in)))}
			out, usage, _, err := runLimited(t, in, lim, m)
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitBlocks || le.Count != 11 {
				t.Fatalf("%s: got %s %d, want blocks count=11", m.name, le.Kind, le.Count)
			}
			if len(out) != 0 || usage.OutputBytes != 0 {
				t.Fatalf("empty blocks produced output: %q / %d", out, usage.OutputBytes)
			}
		}
	})

	t.Run("emptyCompressedBlocks", func(t *testing.T) {
		in := hdr
		for range 1000 {
			// A compressed block containing a single zero token decodes
			// to zero bytes and is still a data block.
			in = cat(in, compBlock([]byte{0}))
		}
		in = cat(in, endMark)
		_, usage, _, err := runLimited(t, in, lz4.Limits{Blocks: limOn(3)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitBlocks || le.Count != 4 {
			t.Fatalf("got %s %d", le.Kind, le.Count)
		}
		if usage.OutputBytes != 0 {
			t.Fatalf("zero-byte blocks charged %d output bytes", usage.OutputBytes)
		}
	})

	t.Run("emptyFrames", func(t *testing.T) {
		var in []byte
		for range 1000 {
			in = cat(in, hdr, endMark)
		}
		_, usage, _, err := runLimited(t, in, lz4.Limits{Frames: limOn(5)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitFrames || le.Count != 6 || usage.Blocks != 0 {
			t.Fatalf("got %s %d, usage blocks=%d", le.Kind, le.Count, usage.Blocks)
		}
	})

	t.Run("skippableStream", func(t *testing.T) {
		var in []byte
		for range 1000 {
			in = cat(in, skippable(0, nil))
		}
		// Each empty skippable frame is 8 bytes: the source cap alone ends
		// the stream even without a frame cap.
		_, _, cr, err := runLimited(t, in, lz4.Limits{SourceBytes: limOn(80)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitSourceBytes {
			t.Fatalf("got %s, want source cap", le.Kind)
		}
		if cr.bytes > 80 {
			t.Fatalf("read %d source bytes past cap 80", cr.bytes)
		}
	})

	t.Run("emptyInput", func(t *testing.T) {
		lim := lz4.Limits{
			SourceBytes: limOn(0), OutputBytes: limOn(0),
			Frames: limOn(0), Blocks: limOn(0), BlockMaxSize: limOn(0),
		}
		out, usage, _, err := runLimited(t, nil, lim, limitedModes[0])
		if err != nil || len(out) != 0 {
			t.Fatalf("empty input: %q, %v", out, err)
		}
		if usage != (lz4.LimitUsage{}) {
			t.Fatalf("empty input counted resources: %+v", usage)
		}
	})
}

// A declared content size can reject a frame early but never stands in for
// the bytes the blocks actually produce.
func TestLimitedReaderContentSize(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	ten := []byte("0123456789")
	comp := compressBlock(t, ten)
	withSize := func(n uint64) []byte { return cat(magic, desc(F|flgSize, bd64K, le64(n)...)) }

	t.Run("hugeRejectedEarly", func(t *testing.T) {
		in := cat(withSize(1<<62), compBlock(comp), endMark)
		lim := lz4.Limits{OutputBytes: limOn(1 << 20)}
		for _, m := range []decodeMode{limitedModes[0], limitedModes[3]} {
			out, usage, cr, err := runLimited(t, in, lim, m)
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitOutputBytes {
				t.Fatalf("%s: got %s", m.name, le.Kind)
			}
			if len(out) != 0 || usage.OutputBytes != 0 {
				t.Fatalf("bytes decoded before early rejection: %q / %d", out, usage.OutputBytes)
			}
			if cr.bytes != 4+3+8 {
				t.Fatalf("%s: read %d source bytes, want 15 (header only)", m.name, cr.bytes)
			}
		}
	})

	t.Run("hugeWithoutLimitVerifiedLater", func(t *testing.T) {
		in := cat(withSize(1<<62), compBlock(comp), endMark)
		_, _, _, err := runLimited(t, in, lz4.Limits{}, limitedModes[0])
		if !errors.Is(err, lz4.ErrInvalidContentSize) {
			t.Fatalf("got %v, want ErrInvalidContentSize", err)
		}
	})

	t.Run("honestSizeExact", func(t *testing.T) {
		in := cat(withSize(10), compBlock(comp), endMark)
		out, _, _, err := runLimited(t, in, lz4.Limits{OutputBytes: limOn(10)}, limitedModes[0])
		if err != nil || !bytes.Equal(out, ten) {
			t.Fatalf("%q, %v", out, err)
		}
	})

	t.Run("declaredDoesNotReplaceCount", func(t *testing.T) {
		// Declared 5, actual 10: the declaration fits but the real block
		// fails the output budget; with no budget, CloseR catches it.
		in := cat(withSize(5), compBlock(comp), endMark)
		_, _, _, err := runLimited(t, in, lz4.Limits{OutputBytes: limOn(7)}, limitedModes[0])
		if !errors.Is(err, lz4.ErrLimitExceeded) {
			t.Fatal("real block output was not counted")
		}
		_, _, _, err = runLimited(t, in, lz4.Limits{}, limitedModes[0])
		if !errors.Is(err, lz4.ErrInvalidContentSize) {
			t.Fatalf("got %v, want ErrInvalidContentSize", err)
		}
	})

	t.Run("overflowAcrossFrames", func(t *testing.T) {
		hdr := cat(magic, desc(F, bd64K))
		first := cat(hdr, rawBlock([]byte("x")), endMark)
		second := withSize(math.MaxUint64)
		in := cat(first, second, endMark)
		lim := lz4.Limits{OutputBytes: limOn(math.MaxUint64)}
		_, usage, _, err := runLimited(t, in, lim, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitOutputBytes || le.Count != math.MaxUint64 {
			t.Fatalf("got %s count=%d", le.Kind, le.Count)
		}
		if usage.OutputBytes != 1 || usage.Frames != 2 {
			t.Fatalf("usage=%+v", usage)
		}
	})
}

// A small compressed block that expands far past the output budget is
// measured and rejected before it is decoded: nothing large is produced.
func TestLimitedReaderCompressedBomb(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	big := bytes.Repeat([]byte("A"), 50000)
	comp := compressBlock(t, big)
	if len(comp) > 1000 {
		t.Fatalf("test premise broken: comp is %d bytes", len(comp))
	}
	hdr := cat(magic, desc(F, bd64K))
	frame := cat(hdr, compBlock(comp), endMark)
	for _, m := range limitedModes {
		t.Run(m.name, func(t *testing.T) {
			lim := lz4.Limits{OutputBytes: limOn(4096), SourceBytes: limOn(uint64(len(frame)))}
			out, usage, cr, err := runLimited(t, frame, lim, m)
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitOutputBytes || le.Count != 50000 {
				t.Fatalf("got %s count=%d", le.Kind, le.Count)
			}
			if len(out) != 0 || usage.OutputBytes != 0 {
				t.Fatalf("bomb produced %d delivered / %d counted bytes", len(out), usage.OutputBytes)
			}
			// The compressed payload may be read to measure it; it is tiny.
			if uint64(cr.bytes) > uint64(len(frame)) {
				t.Fatalf("read past end of frame: %d", cr.bytes)
			}
		})
	}

	// A structurally invalid compressed block is reported as such, not as a
	// limit error, whatever the budget is.
	bad := cat(hdr, compBlock([]byte{0xF0, 0xFF, 0xFF}), endMark)
	for _, m := range limitedModes {
		t.Run("malformed/"+m.name, func(t *testing.T) {
			_, _, _, err := runLimited(t, bad, lz4.Limits{OutputBytes: limOn(math.MaxUint64)}, m)
			if err == nil || errors.Is(err, lz4.ErrLimitExceeded) {
				t.Fatalf("malformed block reported as %v", err)
			}
		})
	}
}

// Using the full output budget still allows the frame footer to be read and
// verified; only a later block that needs more output fails.
func TestLimitedReaderBudgetExactFooter(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	ten := []byte("0123456789")
	ckHdr := cat(magic, desc(F|flgCntCk, bd64K))
	frame := cat(ckHdr, rawBlock(ten), endMark, xxh(ten))

	t.Run("footerStillVerified", func(t *testing.T) {
		for _, m := range limitedModes {
			out, _, _, err := runLimited(t, frame, lz4.Limits{OutputBytes: limOn(10)}, m)
			if err != nil || !bytes.Equal(out, ten) {
				t.Fatalf("%s: %q, %v", m.name, out, err)
			}
		}
	})

	t.Run("emptyBlockAfterExact", func(t *testing.T) {
		in := cat(ckHdr, rawBlock(ten), rawBlock(nil), endMark, xxh(ten))
		out, _, _, err := runLimited(t, in, lz4.Limits{OutputBytes: limOn(10)}, limitedModes[0])
		if err != nil || !bytes.Equal(out, ten) {
			t.Fatalf("%q, %v", out, err)
		}
	})

	t.Run("nonEmptyBlockAfterExact", func(t *testing.T) {
		eleven := append(append([]byte{}, ten...), 'x')
		in := cat(ckHdr, rawBlock(ten), rawBlock([]byte("x")), endMark, xxh(eleven))
		cr := &countingReader{data: in}
		zr := lz4.NewLimitedReader(cr, lz4.Limits{OutputBytes: limOn(10)})
		out, err := io.ReadAll(zr)
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitOutputBytes || le.Count != 11 || !bytes.Equal(out, ten) {
			t.Fatalf("kind=%s count=%d out=%q", le.Kind, le.Count, out)
		}
		// The offending raw block's payload is not pulled from the source.
		// Up to its 4-byte size field may be read; the 'x' byte must not.
		if uint64(cr.bytes) >= uint64(len(in)) {
			t.Fatalf("source fully consumed despite over-budget block: %d", cr.bytes)
		}
	})

	t.Run("nextFrameAfterExact", func(t *testing.T) {
		hdr := cat(magic, desc(F, bd64K))
		next := cat(hdr, rawBlock([]byte("x")), endMark)
		in := cat(frame, next)
		out, usage, _, err := runLimited(t, in, lz4.Limits{OutputBytes: limOn(10)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitOutputBytes || le.Count != 11 || !bytes.Equal(out, ten) {
			t.Fatalf("kind=%s count=%d out=%q", le.Kind, le.Count, out)
		}
		if usage.Frames != 2 {
			t.Fatalf("second frame not counted: %+v", usage)
		}
	})
}

// When the destination writer fails, WriteTo stops, the reader goes into its
// error state, and no more source is consumed.
func TestLimitedReaderShortWrite(t *testing.T) {
	data := bytes.Repeat([]byte("block-data-"), 5000)
	frame := encode(t, data, lz4.BlockSizeOption(lz4.Block64Kb))

	errBoom := errors.New("boom")
	for _, m := range []decodeMode{limitedModes[3], limitedModes[4]} {
		t.Run(m.name, func(t *testing.T) {
			cr := &countingReader{data: frame}
			zr := lz4.NewLimitedReader(cr, lz4.Limits{OutputBytes: limOn(uint64(len(data)))})
			if err := zr.Apply(lz4.ConcurrencyOption(m.conc)); err != nil {
				t.Fatal(err)
			}
			w := &failAfterWriter{err: errBoom}
			n, err := zr.WriteTo(w)
			if !errors.Is(err, errBoom) {
				t.Fatalf("got %v, want boom after %d bytes", err, n)
			}
			if n != 100 {
				t.Fatalf("wrote %d, want 100", n)
			}
			reads := cr.reads
			if _, err := zr.Read(make([]byte, 16)); !errors.Is(err, errBoom) && !errors.Is(err, lz4.ErrOptionClosedOrError) {
				// The reader must at least not succeed or report EOF.
				t.Fatalf("Read after failed write: %v", err)
			}
			if cr.reads != reads {
				t.Fatalf("source read after write failure (%d extra calls)", cr.reads-reads)
			}
		})
	}
}

type failAfterWriter struct {
	n   int64
	err error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.n >= 100 {
		return 0, w.err
	}
	n := int64(len(p))
	if w.n+n > 100 {
		n = 100 - w.n
	}
	w.n += n
	if w.n == 100 {
		return int(n), w.err
	}
	return int(n), nil
}

// Output is reserved when decoded, including bytes still buffered inside the
// Reader, and a switch from Read to WriteTo keeps the same accounting.
func TestLimitedReaderPartialReadWriteTo(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	data := bytes.Repeat([]byte("0123456789"), 40) // 400 bytes, one raw block
	hdr := cat(magic, desc(F, bd64K))
	frame := cat(hdr, rawBlock(data), endMark)

	t.Run("bufferedCountedBeforeDelivery", func(t *testing.T) {
		cr := &countingReader{data: frame}
		zr := lz4.NewLimitedReader(cr, lz4.Limits{OutputBytes: limOn(uint64(len(data)))})
		p := make([]byte, 1)
		n, err := zr.Read(p)
		if err != nil || n != 1 {
			t.Fatalf("first Read: n=%d err=%v", n, err)
		}
		u := zr.Usage()
		if u.OutputBytes != uint64(len(data)) {
			t.Fatalf("only %d output bytes counted after decoding a %d-byte block", u.OutputBytes, len(data))
		}
		var rest bytes.Buffer
		if _, err := zr.WriteTo(&rest); err != nil {
			t.Fatal(err)
		}
		if rest.Len() != len(data)-1 {
			t.Fatalf("WriteTo delivered %d, want %d", rest.Len(), len(data)-1)
		}
	})

	t.Run("reserveBeforeFirstDelivery", func(t *testing.T) {
		cr := &countingReader{data: frame}
		zr := lz4.NewLimitedReader(cr, lz4.Limits{OutputBytes: limOn(uint64(len(data) - 1))})
		p := make([]byte, 1)
		n, err := zr.Read(p)
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitOutputBytes || n != 0 {
			t.Fatalf("n=%d kind=%s", n, le.Kind)
		}
		if zr.Usage().OutputBytes != 0 {
			t.Fatalf("rejected block charged")
		}
	})

	t.Run("writeToAfterPartialExact", func(t *testing.T) {
		cr := &countingReader{data: frame}
		zr := lz4.NewLimitedReader(cr, lz4.Limits{OutputBytes: limOn(uint64(len(data)))})
		head := make([]byte, 123)
		n, err := io.ReadFull(zr, head)
		if err != nil || n != 123 {
			t.Fatalf("ReadFull: n=%d err=%v", n, err)
		}
		var rest bytes.Buffer
		wn, err := zr.WriteTo(&rest)
		if err != nil {
			t.Fatal(err)
		}
		if wn != int64(len(data))-123 {
			t.Fatalf("WriteTo n=%d", wn)
		}
	})
}

// 32- and 64-bit size fields must be checked without overflow or allocation
// proportional to the claimed size.
func TestLimitedReaderLargeFields(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	hdr := cat(magic, desc(F, bd64K))

	t.Run("rawSizeMaxUint32", func(t *testing.T) {
		in := cat(hdr, le32(0xFFFFFFFF))
		for _, m := range limitedModes {
			_, _, _, err := runLimited(t, in, lz4.Limits{}, m)
			if !errors.Is(err, lz4.ErrOptionInvalidBlockSize) {
				t.Fatalf("%s: got %v", m.name, err)
			}
		}
	})

	t.Run("skippableMaxSize", func(t *testing.T) {
		in := cat(le32(0x184D2A5F), le32(0xFFFFFFFF), []byte("abc"))
		// The budget covers exactly the magic and the 4GiB size field: the
		// payload copy is refused its first byte.
		lim := lz4.Limits{SourceBytes: limOn(8)}
		for _, m := range []decodeMode{limitedModes[0], limitedModes[2]} {
			_, _, cr, err := runLimited(t, in, lim, m)
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitSourceBytes {
				t.Fatalf("%s: got %v", m.name, err)
			}
			if cr.bytes != 8 {
				t.Fatalf("%s: read %d bytes, want 8", m.name, cr.bytes)
			}
		}
	})

	t.Run("contentSizeMaxUint64", func(t *testing.T) {
		in := cat(magic, desc(F|flgSize, bd64K, le64(math.MaxUint64)...), endMark)
		_, _, cr, err := runLimited(t, in, lz4.Limits{OutputBytes: limOn(math.MaxUint64 - 1)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitOutputBytes || le.Count != math.MaxUint64 {
			t.Fatalf("got %s count=%d", le.Kind, le.Count)
		}
		if cr.bytes != 15 {
			t.Fatalf("read %d bytes, want 15", cr.bytes)
		}
	})

	t.Run("blockSizeFieldBeyondDescriptor", func(t *testing.T) {
		// 64KiB frame, raw block claiming 64KiB+1: rejected as before.
		in := cat(hdr, le32(uint32(lz4.Block64Kb)+1|1<<31))
		_, _, _, err := runLimited(t, in, lz4.Limits{BlockMaxSize: limOn(uint64(lz4.Block64Kb))}, limitedModes[0])
		if !errors.Is(err, lz4.ErrOptionInvalidBlockSize) {
			t.Fatalf("got %v", err)
		}
	})
}

// Every read reaching the underlying source asks for no more than the
// remaining source budget.
func TestLimitedReaderUnderlyingReadCaps(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	in := cat(cat(magic, desc(F, bd64K)), rawBlock(bytes.Repeat([]byte("xy"), 300)), endMark)
	const budget = 40
	cr := &countingReader{data: in, expect: budget}
	zr := lz4.NewLimitedReader(cr, lz4.Limits{SourceBytes: limOn(budget)})
	_, err := io.Copy(io.Discard, zr)
	le := asLimitError(t, err)
	if le.Kind != lz4.LimitSourceBytes {
		t.Fatalf("got %v", err)
	}
	if cr.violated != 0 {
		t.Fatalf("%d underlying read(s) requested more than the remaining budget", cr.violated)
	}
	if cr.bytes != budget {
		t.Fatalf("delivered %d bytes, want exactly %d", cr.bytes, budget)
	}
}

// Reset explicitly chooses whether the limits survive.
func TestLimitedReaderReset(t *testing.T) {
	F := byte(flgV1 | flgIndep)
	hdr4M := cat(magic, desc(F, 7<<4))
	bigFrame := cat(hdr4M, endMark)
	small := cat(cat(magic, desc(F, bd64K)), rawBlock([]byte("ok")), endMark)

	zr := lz4.NewLimitedReader(bytes.NewReader(bigFrame), lz4.Limits{BlockMaxSize: limOn(64 << 10)})
	if _, err := io.Copy(io.Discard, zr); !errors.Is(err, lz4.ErrLimitExceeded) {
		t.Fatalf("big frame: %v", err)
	}

	// keepLimits: zeroed counters, same caps.
	zr.Reset(bytes.NewReader(small), true)
	if u := zr.Usage(); u != (lz4.LimitUsage{}) {
		t.Fatalf("counters not zeroed: %+v", u)
	}
	if out, err := io.ReadAll(zr); err != nil || string(out) != "ok" {
		t.Fatalf("keepLimits small frame: %q, %v", out, err)
	}

	// Big frame is rejected again with the kept limits.
	zr.Reset(bytes.NewReader(bigFrame), true)
	if _, err := io.Copy(io.Discard, zr); !errors.Is(err, lz4.ErrLimitExceeded) {
		t.Fatalf("limits not kept: %v", err)
	}

	// keepLimits=false: the reader is unlimited.
	zr.Reset(bytes.NewReader(bigFrame), false)
	if _, err := io.Copy(io.Discard, zr); err != nil {
		t.Fatalf("limits not dropped: %v", err)
	}
}

// Legacy frames are capped like regular ones; the 8MiB block size gate and
// concatenated-frame counting apply.
func TestLimitedReaderLegacy(t *testing.T) {
	data := bytes.Repeat([]byte("legacy "), 100)
	frame := encode(t, data, lz4.LegacyOption(true))

	t.Run("outputExact", func(t *testing.T) {
		out, usage, _, err := runLimited(t, frame, lz4.Limits{OutputBytes: limOn(uint64(len(data)))}, limitedModes[0])
		if err != nil || !bytes.Equal(out, data) {
			t.Fatalf("%q, %v", out, err)
		}
		if usage.OutputBytes != uint64(len(data)) || usage.Frames != 1 {
			t.Fatalf("usage=%+v", usage)
		}
	})
	t.Run("outputOver", func(t *testing.T) {
		_, _, _, err := runLimited(t, frame, lz4.Limits{OutputBytes: limOn(uint64(len(data) - 1))}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitOutputBytes {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("blockSize8MiBGate", func(t *testing.T) {
		_, _, cr, err := runLimited(t, frame, lz4.Limits{BlockMaxSize: limOn(4 << 20)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitBlockSize || le.Count != 8<<20 {
			t.Fatalf("got %s count=%d", le.Kind, le.Count)
		}
		// Only the legacy magic precedes the gate.
		if cr.bytes != 4 {
			t.Fatalf("read %d bytes, want 4", cr.bytes)
		}
	})
	t.Run("concatenatedFrames", func(t *testing.T) {
		two := cat(frame, frame)
		out, usage, _, err := runLimited(t, two, lz4.Limits{Frames: limOn(1)}, limitedModes[0])
		le := asLimitError(t, err)
		if le.Kind != lz4.LimitFrames || le.Count != 2 {
			t.Fatalf("got %s %d", le.Kind, le.Count)
		}
		if !bytes.Equal(out, data) {
			t.Fatalf("first legacy frame output: got %d bytes, want %d", len(out), len(data))
		}
		// The rejected second frame is reported in the error count, but the
		// rejected reservation is not added to the usage counters.
		if usage.Frames != 1 {
			t.Fatalf("usage frames=%d, want 1 counted and 1 attempted", usage.Frames)
		}
	})
}

// The concurrency option is honored rather than silently dropped: a
// LimitedReader asked to read ahead still exercises that path, and both
// schedules produce the same limit verdicts (covered throughout the file);
// this test pins the choice visibly.
func TestLimitedReaderConcurrencyHonored(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefgh"), 50000) // several 64KiB blocks
	frame := encode(t, data, lz4.BlockSizeOption(lz4.Block64Kb))
	for _, conc := range []int{1, 4} {
		t.Run(fmt.Sprintf("conc%d", conc), func(t *testing.T) {
			cr := &countingReader{data: frame}
			zr := lz4.NewLimitedReader(cr, lz4.Limits{OutputBytes: limOn(uint64(len(data) / 2))})
			if err := zr.Apply(lz4.ConcurrencyOption(conc)); err != nil {
				t.Fatal(err)
			}
			_, err := io.Copy(io.Discard, zr)
			le := asLimitError(t, err)
			if le.Kind != lz4.LimitOutputBytes {
				t.Fatalf("got %v", err)
			}
		})
	}
}
