package lz4_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/pierrec/lz4/v4/internal/lz4block"
	"github.com/pierrec/lz4/v4/internal/xxh32"
)

// The tests in this file exercise Reframe, which concatenates plain LZ4
// frames into one without recompressing. The output structure is checked with
// an independent byte-level parser that only shares the block decoder, and
// decompressed output is also checked through Reader.

const (
	reframeMagic       uint32 = 0x184D2204
	reframeSkipMagic   uint32 = 0x184D2A50
	reframeLegacyMagic uint32 = 0x184C2102
)

// reframeBlock is one data block as found on the wire.
type reframeBlock struct {
	field   uint32 // raw 4-byte size field, including the raw flag
	payload []byte // stored bytes, copied out of the frame
	content []byte // decoded bytes
}

type reframeParsed struct {
	flg, bd   byte
	hasSize   bool
	size      uint64
	blocks    []reframeBlock
	content   []byte
	frameEnds int // offset just past this frame
}

// reframeParseFrames parses all complete frames in b independently of
// Reader. It returns an error on anything malformed, and trailer counts bytes
// after the last frame (0 for a clean stream).
func reframeParseFrames(t testing.TB, b []byte) ([]reframeParsed, int, error) {
	t.Helper()
	blockMaxBuf := make([]byte, 4<<20)
	var frames []reframeParsed
	off := 0
	for off < len(b) {
		start := off
		if len(b)-off < 4 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		if magic := binary.LittleEndian.Uint32(b[off:]); magic != reframeMagic {
			return nil, 0, fmt.Errorf("bad magic %#x", magic)
		}
		off += 4
		if len(b)-off < 3 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		flg, bd := b[off], b[off+1]
		desc := b[off : off+2]
		off += 2
		var p reframeParsed
		p.flg, p.bd = flg, bd
		if flg&(1<<3) != 0 { // content size
			if len(b)-off < 8 {
				return nil, 0, io.ErrUnexpectedEOF
			}
			p.hasSize = true
			p.size = binary.LittleEndian.Uint64(b[off:])
			desc = b[start+4 : off+8]
			off += 8
		}
		if flg&1 != 0 { // dictionary ID
			if len(b)-off < 4 {
				return nil, 0, io.ErrUnexpectedEOF
			}
			desc = b[start+4 : off+4]
			off += 4
		}
		hc := b[off]
		off++
		if got := byte(xxh32.ChecksumZero(desc) >> 8); got != hc {
			return nil, 0, fmt.Errorf("header checksum %#x want %#x", got, hc)
		}
		if flg>>6&3 != 1 {
			return nil, 0, fmt.Errorf("version %d", flg>>6&3)
		}
		var blockMax int
		switch idx := bd >> 4 & 7; idx {
		case 4:
			blockMax = 64 << 10
		case 5:
			blockMax = 256 << 10
		case 6:
			blockMax = 1 << 20
		case 7:
			blockMax = 4 << 20
		default:
			return nil, 0, fmt.Errorf("block size index %d", idx)
		}
		var hash xxh32.XXHZero
		for {
			if len(b)-off < 4 {
				return nil, 0, io.ErrUnexpectedEOF
			}
			field := binary.LittleEndian.Uint32(b[off:])
			off += 4
			if field == 0 {
				break
			}
			size := int(field & 0x7fffffff)
			if size > blockMax {
				return nil, 0, fmt.Errorf("block payload %d exceeds %d", size, blockMax)
			}
			if len(b)-off < size {
				return nil, 0, io.ErrUnexpectedEOF
			}
			payload := b[off : off+size]
			off += size
			if flg&(1<<4) != 0 {
				if len(b)-off < 4 {
					return nil, 0, io.ErrUnexpectedEOF
				}
				want := binary.LittleEndian.Uint32(b[off:])
				off += 4
				if got := xxh32.ChecksumZero(payload); got != want {
					return nil, 0, fmt.Errorf("block checksum %#x want %#x", got, want)
				}
			}
			var decoded []byte
			if field&(1<<31) != 0 {
				decoded = payload
			} else {
				n, err := lz4block.UncompressBlock(payload, blockMaxBuf[:blockMax], nil)
				if err != nil {
					return nil, 0, fmt.Errorf("decode: %w", err)
				}
				decoded = blockMaxBuf[:n]
			}
			hash.Write(decoded)
			p.content = append(p.content, decoded...)
			stored := make([]byte, size)
			copy(stored, payload)
			p.blocks = append(p.blocks, reframeBlock{field: field, payload: stored, content: decoded})
		}
		if flg&(1<<2) != 0 {
			if len(b)-off < 4 {
				return nil, 0, io.ErrUnexpectedEOF
			}
			want := binary.LittleEndian.Uint32(b[off:])
			off += 4
			if got := hash.Sum32(); got != want {
				return nil, 0, fmt.Errorf("content checksum %#x want %#x", got, want)
			}
		}
		if p.hasSize && uint64(len(p.content)) != p.size {
			return nil, 0, fmt.Errorf("content size %d want %d", len(p.content), p.size)
		}
		p.frameEnds = off
		frames = append(frames, p)
	}
	return frames, len(b) - off, nil
}

// reframeCraftBlock is one block handed to the hand-built frame writer.
type reframeCraftBlock struct {
	raw      bool
	payload  []byte  // stored bytes
	field    *uint32 // if set, overrides the raw flag and length
	checksum *uint32 // if set, overrides the stored block checksum
}

// reframeCraftFrame assembles a frame from raw descriptor fields and blocks.
func reframeCraftFrame(t testing.TB, flg, bd byte, setSize bool, size uint64, dictID *uint32, blocks []reframeCraftBlock, content []byte, contentChecksum bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], reframeMagic)
	buf.Write(u32[:])
	descStart := buf.Len()
	buf.WriteByte(flg)
	buf.WriteByte(bd)
	if setSize {
		var u64 [8]byte
		binary.LittleEndian.PutUint64(u64[:], size)
		buf.Write(u64[:])
	}
	if dictID != nil {
		binary.LittleEndian.PutUint32(u32[:], *dictID)
		buf.Write(u32[:])
	}
	desc := buf.Bytes()[descStart:]
	buf.WriteByte(byte(xxh32.ChecksumZero(desc) >> 8))
	for _, b := range blocks {
		field := uint32(len(b.payload))
		if b.raw {
			field |= 1 << 31
		}
		if b.field != nil {
			field = *b.field
		}
		binary.LittleEndian.PutUint32(u32[:], field)
		buf.Write(u32[:])
		buf.Write(b.payload)
		if flg&(1<<4) != 0 {
			sum := xxh32.ChecksumZero(b.payload)
			if b.checksum != nil {
				sum = *b.checksum
			}
			binary.LittleEndian.PutUint32(u32[:], sum)
			buf.Write(u32[:])
		}
	}
	buf.Write([]byte{0, 0, 0, 0})
	if contentChecksum {
		binary.LittleEndian.PutUint32(u32[:], xxh32.ChecksumZero(content))
		buf.Write(u32[:])
	}
	return buf.Bytes()
}

func reframeCompress(t testing.TB, src []byte) []byte {
	t.Helper()
	dst := make([]byte, lz4block.CompressBlockBound(len(src)))
	n, err := lz4block.CompressBlock(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("test data incompressible")
	}
	return dst[:n]
}

func reframeDo(t testing.TB, in []byte) ([]byte, int64, error) {
	t.Helper()
	var out bytes.Buffer
	n, err := lz4.Reframe(&out, bytes.NewReader(in))
	return out.Bytes(), n, err
}

// reframeInput is one concatenated input frame with its known content.
type reframeInput struct {
	frame   []byte
	content []byte
}

// TestReframe mixes block sizes, compressed and raw blocks, empty raw blocks
// and empty frames, and every checksum combination, and proves the output is a
// single frame carrying the same payloads in order.
func TestReframe(t *testing.T) {
	var inputs []reframeInput
	add := func(frame, content []byte) {
		inputs = append(inputs, reframeInput{frame: frame, content: content})
	}

	// Empty frame first: it must not end the merge.
	add(encode(t, nil), nil)

	// Checksum matrix over small blocks, with data crossing a block edge.
	data := testData(70000, true, 1)
	for _, bs := range []lz4.BlockSize{lz4.Block64Kb, lz4.Block256Kb} {
		for _, blockCS := range []bool{false, true} {
			for _, contentCS := range []bool{false, true} {
				for _, setSize := range []bool{false, true} {
					opts := []lz4.Option{
						lz4.BlockSizeOption(bs),
						lz4.BlockChecksumOption(blockCS),
						lz4.ChecksumOption(contentCS),
					}
					if setSize {
						opts = append(opts, lz4.SizeOption(uint64(len(data))))
					}
					frame := encode(t, data, opts...)
					add(frame, data)
				}
			}
		}
	}

	// Empty frame without checksums, in the middle.
	var noChecksum bytes.Buffer
	zw := lz4.NewWriter(&noChecksum)
	if err := zw.Apply(lz4.BlockSizeOption(lz4.Block64Kb), lz4.ChecksumOption(false)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	add(noChecksum.Bytes(), nil)

	// Incompressible data is stored raw: 256 KiB blocks, block checksum on,
	// content checksum off.
	random := testData(300000, false, 2)
	add(encode(t, random,
		lz4.BlockSizeOption(lz4.Block256Kb),
		lz4.BlockChecksumOption(true),
		lz4.ChecksumOption(false),
	), random)

	// Declared content size, 1 MiB blocks and more than one block.
	big := testData(2_100_000, true, 3)
	add(encode(t, big,
		lz4.BlockSizeOption(lz4.Block1Mb),
		lz4.BlockChecksumOption(true),
		lz4.SizeOption(uint64(len(big))),
	), big)

	// Hand-built frame with raw empty blocks around a compressed block: the
	// raw flag and the 0x80000000 fields must survive and stay distinct from
	// the EndMark.
	mid := testData(100000, true, 4)
	midZ := reframeCompress(t, mid)
	var craftedContent bytes.Buffer
	craftedContent.WriteString("hello")
	craftedContent.Write(mid)
	craftedContent.WriteString("world")
	const craftedFLG = 0x40 | 0x20 | 0x10 | 0x04 // version, independent, block and content checksums
	crafted := reframeCraftFrame(t, craftedFLG, 0x50 /*256 KiB*/, false, 0, nil, []reframeCraftBlock{
		{raw: true, payload: []byte("hello")},
		{raw: true, payload: nil}, // raw empty block
		{raw: false, payload: midZ},
		{raw: true, payload: nil}, // raw empty block
		{raw: true, payload: []byte("world")},
	}, craftedContent.Bytes(), true)
	add(crafted, craftedContent.Bytes())

	// One-byte frame with every checksum.
	add(encode(t, []byte("x"),
		lz4.BlockSizeOption(lz4.Block64Kb),
		lz4.BlockChecksumOption(true),
	), []byte("x"))

	if thorough() {
		// Multiple 4 MiB blocks in one frame.
		huge := testData(4<<20+1000, true, 5)
		add(encode(t, huge, lz4.BlockSizeOption(lz4.Block4Mb)), huge)
		// Raw blocks at 4 MiB.
		hugeRaw := testData(4<<20+1000, false, 6)
		add(encode(t, hugeRaw, lz4.BlockSizeOption(lz4.Block4Mb),
			lz4.BlockChecksumOption(true)), hugeRaw)
	}

	// Empty frame last as well.
	add(encode(t, nil), nil)

	var stream bytes.Buffer
	var wantContent bytes.Buffer
	var wantBlocks []reframeBlock
	var rawBlocks, compressedBlocks, emptyRawBlocks int
	for _, in := range inputs {
		stream.Write(in.frame)
		frames, trailer, err := reframeParseFrames(t, in.frame)
		if err != nil {
			t.Fatalf("input frame parse: %v", err)
		}
		if trailer != 0 || len(frames) != 1 {
			t.Fatalf("input is not one frame: %d frames, %d trailer", len(frames), trailer)
		}
		for _, b := range frames[0].blocks {
			wantBlocks = append(wantBlocks, b)
			if b.field&(1<<31) != 0 {
				rawBlocks++
				if len(b.payload) == 0 {
					emptyRawBlocks++
				}
			} else {
				compressedBlocks++
			}
		}
		if !bytes.Equal(frames[0].content, in.content) {
			t.Fatalf("reference decode mismatch: %d vs %d bytes", len(frames[0].content), len(in.content))
		}
		wantContent.Write(in.content)
	}
	if rawBlocks == 0 || compressedBlocks == 0 || emptyRawBlocks == 0 {
		t.Fatalf("expected raw, compressed and empty raw blocks, got %d/%d/%d",
			rawBlocks, compressedBlocks, emptyRawBlocks)
	}

	// Reframe, once through a normal buffer and once a byte at a time.
	out, n, err := reframeDo(t, stream.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(out)) {
		t.Fatalf("reported %d bytes, wrote %d", n, len(out))
	}
	var slow bytes.Buffer
	if _, err := lz4.Reframe(&slow, &oneByteReader{b: stream.Bytes()}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(slow.Bytes(), out) {
		t.Fatal("output differs when the source returns one byte per Read")
	}

	// Fixed 7-byte header: magic, FLG 0x74, BD 0x70 (4 MiB), descriptor checksum.
	wantHC := byte(xxh32.ChecksumZero([]byte{0x74, 0x70}) >> 8)
	if want := []byte{0x04, 0x22, 0x4d, 0x18, 0x74, 0x70, wantHC}; !bytes.Equal(out[:7], want) {
		t.Fatalf("header % x want % x", out[:7], want)
	}

	frames, trailer, err := reframeParseFrames(t, out)
	if err != nil {
		t.Fatalf("output parse: %v", err)
	}
	if len(frames) != 1 || trailer != 0 {
		t.Fatalf("output is %d frames with %d trailer bytes", len(frames), trailer)
	}
	of := frames[0]
	if of.flg != 0x74 || of.bd != 0x70 || of.hasSize {
		t.Fatalf("output descriptor flg=%#02x bd=%#02x size=%v", of.flg, of.bd, of.hasSize)
	}
	if len(of.blocks) != len(wantBlocks) {
		t.Fatalf("output has %d blocks, want %d", len(of.blocks), len(wantBlocks))
	}
	for i, want := range wantBlocks {
		got := of.blocks[i]
		if got.field != want.field {
			t.Fatalf("block %d: field %#08x want %#08x", i, got.field, want.field)
		}
		if !bytes.Equal(got.payload, want.payload) {
			t.Fatalf("block %d: payload changed (%d vs %d bytes)", i, len(got.payload), len(want.payload))
		}
	}
	if !bytes.Equal(of.content, wantContent.Bytes()) {
		t.Fatalf("reference decode of output is %d bytes, want %d", len(of.content), wantContent.Len())
	}
	// Footer: EndMark plus content checksum were written exactly once, at end.
	if !bytes.Equal(out[len(out)-8:len(out)-4], []byte{0, 0, 0, 0}) {
		t.Fatal("output does not end with the EndMark")
	}

	// The existing Reader must decode the merged frame to the same bytes,
	// both serially and concurrently.
	for _, conc := range []int{1, 4} {
		r := lz4.NewReader(bytes.NewReader(out))
		if err := r.Apply(lz4.ConcurrencyOption(conc)); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("Reader conc=%d: %v", conc, err)
		}
		if !bytes.Equal(got, wantContent.Bytes()) {
			t.Fatalf("Reader conc=%d decoded %d bytes, want %d", conc, len(got), wantContent.Len())
		}
	}
}

func TestReframeEmptyInput(t *testing.T) {
	var out bytes.Buffer
	n, err := lz4.Reframe(&out, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(out.Len()) || out.Len() != 7+8 {
		t.Fatalf("empty frame is %d bytes (n=%d)", out.Len(), n)
	}
	frames, trailer, err := reframeParseFrames(t, out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || trailer != 0 || len(frames[0].blocks) != 0 || len(frames[0].content) != 0 {
		t.Fatalf("unexpected empty output: %+v", frames)
	}
	r := lz4.NewReader(bytes.NewReader(out.Bytes()))
	got, err := io.ReadAll(r)
	if err != nil || len(got) != 0 {
		t.Fatalf("Reader on empty output: %d bytes, err=%v", len(got), err)
	}
}

func TestReframeRejects(t *testing.T) {
	good := encode(t, testData(100000, true, 7),
		lz4.BlockSizeOption(lz4.Block64Kb),
		lz4.BlockChecksumOption(true),
	)
	goodCS := encode(t, []byte("content checksum"),
		lz4.BlockSizeOption(lz4.Block64Kb))
	var u32 [4]byte
	putU32 := func(v uint32) []byte {
		binary.LittleEndian.PutUint32(u32[:], v)
		return append([]byte(nil), u32[:]...)
	}

	// A valid block whose payload decompresses beyond the frame's 64 KiB
	// bound: 100 KiB compressible data compressed small.
	over := testData(100000, true, 8)
	overZ := reframeCompress(t, over)
	overBound := reframeCraftFrame(t, 0x40|0x20, 0x40, false, 0, nil,
		[]reframeCraftBlock{{payload: overZ}}, over, true)

	// A raw block that declares more than the frame maximum.
	badField := uint32(70000)
	oversizeRaw := reframeCraftFrame(t, 0x40|0x20, 0x40, false, 0, nil,
		[]reframeCraftBlock{{field: &badField, payload: make([]byte, 70000)}}, nil, false)

	// Block-dependent and dictionary frames, and reserved/version bits.
	dependent := reframeCraftFrame(t, 0x40|0x04, 0x40, false, 0, nil,
		[]reframeCraftBlock{{raw: true, payload: []byte("x")}}, []byte("x"), true)
	dict := uint32(42)
	dictionary := reframeCraftFrame(t, 0x40|0x20|0x01, 0x40, false, 0, &dict,
		nil, nil, false)
	reserved := reframeCraftFrame(t, 0x40|0x20|0x02, 0x40, false, 0, nil, nil, nil, false)
	badVersion := reframeCraftFrame(t, 0x00|0x20, 0x40, false, 0, nil, nil, nil, false)

	// Wrong block checksum on an otherwise valid frame.
	wrongCS := uint32(0xdeadbeef)
	badBlockCS := reframeCraftFrame(t, 0x40|0x20|0x10|0x04, 0x40, false, 0, nil,
		[]reframeCraftBlock{{raw: true, payload: []byte("x"), checksum: &wrongCS}},
		[]byte("x"), true)

	// Declared content size that disagrees with the data.
	badSize := reframeCraftFrame(t, 0x40|0x20|0x04|0x08, 0x40, true, 99, nil,
		[]reframeCraftBlock{{raw: true, payload: []byte("x")}}, []byte("x"), true)

	// Corrupt a compressed payload byte in a frame without block checksums:
	// decoding or the content checksum must catch it.
	corrupt := append([]byte(nil), goodCS...)
	corrupt[7+4+2] ^= 0xff

	skippable := append(putU32(reframeSkipMagic), putU32(0)...)
	skippableHi := append(putU32(reframeSkipMagic|0xf), putU32(0)...)

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"legacy", append(putU32(reframeLegacyMagic), 0), lz4.ErrInvalidFrame},
		{"skippable before", append(append([]byte(nil), skippable...), good...), lz4.ErrInvalidFrame},
		{"skippable after", append(append([]byte(nil), good...), skippable...), lz4.ErrInvalidFrame},
		{"skippable hi variant", append(append([]byte(nil), good...), skippableHi...), lz4.ErrInvalidFrame},
		{"dependent", dependent, lz4.ErrInvalidFrameDescriptor},
		{"dictionary", dictionary, lz4.ErrInvalidFrameDescriptor},
		{"reserved bits", reserved, lz4.ErrInvalidFrameDescriptor},
		{"bad version", badVersion, lz4.ErrInvalidFrameDescriptor},
		{"encoded over block max", oversizeRaw, lz4.ErrOptionInvalidBlockSize},
		{"decoded over block max", overBound, lz4.ErrInvalidSourceShortBuffer},
		{"bad block checksum", badBlockCS, lz4.ErrInvalidBlockChecksum},
		{"bad content size", badSize, lz4.ErrInvalidContentSize},
		{"bad content checksum", withByte(goodCS, len(goodCS)-1, goodCS[len(goodCS)-1]^0xff), lz4.ErrInvalidFrameChecksum},
		{"corrupt payload", corrupt, nil},
		{"trailing garbage", append(append([]byte(nil), good...), 1, 2, 3, 4), lz4.ErrInvalidFrame},
		{"trailing two bytes", append(append([]byte(nil), good...), 1, 2), io.ErrUnexpectedEOF},
		{"truncated frame", goodCS[:len(goodCS)-1], io.ErrUnexpectedEOF},
		{"truncated header", putU32(reframeMagic), io.ErrUnexpectedEOF},
		{"bad magic", putU32(0xdeadbeef), lz4.ErrInvalidFrame},
		{"bad header checksum", withByte(good, 6, good[6]^0xff), lz4.ErrInvalidHeaderChecksum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var prefix bytes.Buffer
			n, err := lz4.Reframe(&prefix, bytes.NewReader(tc.in))
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if n != int64(prefix.Len()) {
				t.Fatalf("reported %d bytes, prefix is %d", n, prefix.Len())
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error %v does not wrap %v", err, tc.want)
			}
			// The prefix must never look like a successfully closed frame.
			if prefix.Len() == 0 {
				return
			}
			if frames, trailer, perr := reframeParseFrames(t, prefix.Bytes()); perr == nil {
				for _, f := range frames {
					if f.frameEnds == prefix.Len() && trailer == 0 {
						t.Fatal("error left a prefix that parses as a complete frame")
					}
				}
			}
		})
	}
}

func withByte(b []byte, i int, v byte) []byte {
	out := append([]byte(nil), b...)
	out[i] = v
	return out
}

// TestReframeDestinationFailures covers short writes, zero-progress writes
// and failures at every stage: Reframe must report the error, count accepted
// bytes, and never append a footer.
func TestReframeDestinationFailures(t *testing.T) {
	reference := encode(t, testData(200000, true, 9),
		lz4.BlockSizeOption(lz4.Block64Kb),
		lz4.BlockChecksumOption(true),
	)
	empty := encode(t, nil)
	input := append(append([]byte(nil), reference...), empty...)
	want := reframeMust(t, input)

	// A destination that accepts only a few bytes per call still produces
	// the exact same frame.
	for _, max := range []int{1, 2, 3, 7, 4096} {
		var got bytes.Buffer
		if _, err := lz4.Reframe(&shortWriter{max: max, dst: &got}, bytes.NewReader(input)); err != nil {
			t.Fatalf("max=%d: %v", max, err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("max=%d: %d bytes, want %d", max, got.Len(), len(want))
		}
	}

	// (0, nil) violates the io.Writer contract and must surface as short write.
	if _, err := lz4.Reframe(zeroWriter{}, bytes.NewReader(input)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v, want io.ErrShortWrite", err)
	}

	// Failures at increasing offsets never leave a closed frame behind.
	failErr := errors.New("destination gone")
	positions := map[int64]bool{0: true, 1: true, 6: true, 7: true, 8: true, 11: true, 100: true,
		int64(len(want)) / 4: true, int64(len(want)) / 2: true,
		int64(len(want)) - 5: true, int64(len(want)) - 1: true}
	for at := range positions {
		w := &failWriter{failAt: at, err: failErr}
		n, err := lz4.Reframe(w, bytes.NewReader(input))
		if !errors.Is(err, failErr) {
			t.Fatalf("at=%d: got %v, want injected error", at, err)
		}
		if n != int64(w.buf.Len()) {
			t.Fatalf("at=%d: reported %d, prefix is %d", at, n, w.buf.Len())
		}
		if w.buf.Len() >= len(want) {
			t.Fatalf("at=%d: failure wrote the whole frame", at)
		}
		if bytes.Equal(w.buf.Bytes(), want) {
			t.Fatalf("at=%d: prefix is the complete output", at)
		}
	}
}

func reframeMust(t testing.TB, in []byte) []byte {
	t.Helper()
	out, _, err := reframeDo(t, in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type oneByteReader struct {
	b []byte
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.b[0]
	r.b = r.b[1:]
	return 1, nil
}

type shortWriter struct {
	max int
	dst io.Writer
}

func (w shortWriter) Write(p []byte) (int, error) {
	n := w.max
	if n > len(p) {
		n = len(p)
	}
	_, err := w.dst.Write(p[:n])
	return n, err
}

type zeroWriter struct{}

func (zeroWriter) Write(p []byte) (int, error) { return 0, nil }

type failWriter struct {
	buf    bytes.Buffer
	failAt int64
	err    error
}

func (w *failWriter) Write(p []byte) (int, error) {
	avail := int(w.failAt - int64(w.buf.Len()))
	if avail <= 0 {
		return 0, w.err
	}
	if avail > len(p) {
		avail = len(p)
	}
	w.buf.Write(p[:avail])
	if avail < len(p) {
		return avail, w.err
	}
	return len(p), nil
}
