package lz4

import (
	"io"

	"github.com/pierrec/lz4/v4/internal/lz4stream"
)

// Reframe merges the concatenation of plain LZ4 frames read from src into one
// plain frame written to dst, without recompressing. Each input data block is
// copied byte for byte, in order: its compressed or raw payload bytes and its
// uncompressed (raw) flag are preserved, and the compressor is never called.
//
// The output frame always uses a 4 MiB maximum block size, block checksums and
// a content checksum, and declares no content size, so it is produced in one
// pass. Input frames may use other maximum block sizes and other checksum
// settings. Empty input frames do not end the merge; an empty src yields one
// valid empty output frame.
//
// Integrity is checked even though payloads are copied: each input block's
// encoded length and decoded size are bounded by its frame's maximum block
// size, a block checksum is read and verified when the frame carries one, and
// every block is decoded, both to verify the input content checksum and
// declared content size and to compute the output content checksum. Output
// block checksums are computed over the payload bytes actually written; a raw
// empty block is kept distinct from the EndMark. Input EndMarks and content
// checksums are consumed but not copied: exactly one EndMark and the total
// content checksum are written, and only after every input frame has been
// read and verified.
//
// Legacy frames, block-dependent frames, dictionary frames, skippable frames
// and trailing bytes that are not another frame are rejected with an error.
// Memory use is proportional to the largest single block, not to the input;
// decompressed content is streamed rather than buffered.
//
// If reading src or writing dst fails partway through, dst may contain an
// unclosed frame prefix: Reframe returns the error and does not append a
// footer that would make it look like a complete frame. It does not attempt to
// undo bytes already accepted by dst, since an arbitrary io.Writer cannot be
// rewound. The returned count is the number of bytes written to dst,
// including any prefix.
func Reframe(dst io.Writer, src io.Reader) (int64, error) {
	return lz4stream.Reframe(dst, src)
}
