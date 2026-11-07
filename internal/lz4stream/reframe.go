package lz4stream

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4/internal/lz4block"
	"github.com/pierrec/lz4/v4/internal/lz4errors"
	"github.com/pierrec/lz4/v4/internal/xxh32"
)

// Reframe merges the plain, block-independent, dictionary-free LZ4 frames
// read from src into a single plain frame written to dst. Compressed and raw
// block payloads are copied byte for byte, in order, and never recompressed.
//
// The output frame always uses a 4 MiB maximum block size, block checksums and
// a content checksum, and declares no content size, so it is written in one
// pass. Every input block is decoded: its encoded length and decoded size are
// bounded by the input frame's maximum block size, an input block checksum is
// checked when present, and decoded data verifies the input content checksum
// and size while feeding the output content checksum. Input EndMarks and
// content checksums are not copied; one of each ends the output only after
// every input frame has been fully read and verified.
//
// Legacy, block-dependent, dictionary and skippable frames, as well as any
// trailing bytes that are not another frame, are rejected.
//
// On error the output may already contain an unclosed frame prefix: Reframe
// returns the error without writing an end mark or checksum, and does not
// undo bytes already accepted by dst. The returned count is the number of
// bytes written, including that prefix.
func Reframe(dst io.Writer, src io.Reader) (int64, error) {
	r := &reframer{dst: dst, src: src}
	err := r.run()
	return r.n, err
}

type reframer struct {
	dst io.Writer
	src io.Reader
	n   int64
}

// Write satisfies io.Writer with a full-write on top of dst, so a destination
// that returns a short count without an error does not corrupt the frame.
// Like io.Writer, it may return a positive count together with an error.
func (r *reframer) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		m, err := r.dst.Write(p)
		r.n += int64(m)
		if err != nil {
			return written - len(p), err
		}
		if m <= 0 || m > len(p) {
			return written - len(p), io.ErrShortWrite
		}
		p = p[m:]
	}
	return written, nil
}

func (r *reframer) run() error {
	// Single output frame: version 1, independent blocks, 4 MiB maximum
	// block size, block and content checksums, no content size.
	var out Frame
	out.Magic = frameMagic
	out.Descriptor.initW()
	out.Descriptor.Flags.BlockSizeIndexSet(lz4block.Index(lz4block.Block4Mb))
	out.Descriptor.Flags.BlockChecksumSet(true)
	out.Descriptor.Flags.ContentChecksumSet(true)
	if err := out.Descriptor.Write(&out, r); err != nil {
		return err
	}
	out.checksum.Reset()
	out.size = 0

	var in Frame
	var magic [4]byte
	for {
		// Only a frame boundary is a legal place for end of input.
		if _, err := io.ReadFull(r.src, magic[:]); err != nil {
			if err == io.EOF {
				return r.close(&out)
			}
			return unexpectedEOF(err)
		}
		switch m := binary.LittleEndian.Uint32(magic[:]); {
		case m == frameMagic:
			in.Magic = m
		case m == frameMagicLegacy:
			return fmt.Errorf("%w: legacy frame is not supported", lz4errors.ErrInvalidFrame)
		case m>>8 == frameSkipMagic>>8:
			return fmt.Errorf("%w: skippable frame is not supported", lz4errors.ErrInvalidFrame)
		default:
			return lz4errors.ErrInvalidFrame
		}
		if err := r.mergeFrame(&in, &out); err != nil {
			return err
		}
	}
}

// mergeFrame reads one input frame after its magic number and appends its
// blocks, verbatim, to the output frame.
func (r *reframer) mergeFrame(in, out *Frame) error {
	if err := in.Descriptor.initR(in, r.src); err != nil {
		return unexpectedEOF(err)
	}
	if !in.Descriptor.Flags.BlockIndependence() {
		return fmt.Errorf("%w: block-dependent frame is not supported", lz4errors.ErrInvalidFrameDescriptor)
	}
	in.checksum.Reset()
	in.size = 0

	idx := in.Descriptor.Flags.BlockSizeIndex()
	block := NewFrameDataBlock(in) // payload buffer, capped at the frame maximum
	plain := idx.Get()             // decoded data, capped at the frame maximum
	defer lz4block.Put(plain)
	defer block.Close(in)

	for {
		if _, err := block.Read(in, r.src, 0); err != nil {
			if err == lz4errors.ErrEndOfStream {
				break
			}
			return err
		}
		// Decode within the input frame's bound: a raw copy is bounded too.
		// With sum set, this also verifies the input block checksum and
		// accumulates the input content checksum and size.
		content, err := block.Uncompress(in, plain[:cap(plain)], nil, true)
		if err != nil {
			return err
		}
		// Emit the block unchanged: the size field, including the raw flag,
		// and the payload bytes are copied as stored. The output always has
		// block checksums, so compute one over the actual payload.
		var ob FrameDataBlock
		ob.Size = block.Size
		ob.Data = block.data
		ob.src = content
		ob.Checksum = xxh32.ChecksumZero(block.data)
		if err := ob.Write(out, r); err != nil {
			return err
		}
	}

	// Reads and verifies the input content checksum and declared size.
	return in.CloseR(r.src)
}

// close writes the sole output end mark and content checksum, only once all
// input frames have been read and verified.
func (r *reframer) close(out *Frame) error {
	var footer [8]byte // zero EndMark followed by the content checksum
	binary.LittleEndian.PutUint32(footer[4:], out.checksum.Sum32())
	_, err := r.Write(footer[:])
	return err
}
