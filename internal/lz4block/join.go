package lz4block

import (
	"math"

	"github.com/pierrec/lz4/v4/internal/lz4errors"
)

// JoinBlocks merges two independently compressed LZ4 blocks into one block
// that decompresses to left's data followed by right's. It handles raw
// blocks only: no frame headers, no dictionaries.
//
// Neither the compressor nor a decompressed copy of the inputs is used: the
// blocks are parsed once and copied sequence by sequence. Existing matches
// keep their offset and length bytes verbatim; only left's final
// literals-only sequence and right's first sequence are rewritten, merging
// their literals into one legal sequence. Right's final token is emitted with
// a zero match nibble (the format ignores that nibble in the last sequence).
//
// A block is accepted only if, parsed on its own with no dictionary, every
// offset is non-zero and no larger than the bytes already generated in that
// block. An offset that would only become legal because the join places left
// in front of right is therefore rejected.
//
// maxSize bounds the decompressed size of the result; both inputs and their
// sum are checked against it before the output is allocated. The returned
// slice is freshly allocated and never shares the inputs' backing arrays.
func JoinBlocks(left, right []byte, maxSize int) (out []byte, err error) {
	if maxSize < 0 {
		return nil, lz4errors.ErrInvalidSourceShortBuffer
	}
	l, err := parseBlock(left, uint64(maxSize))
	if err != nil {
		return nil, err
	}
	// Parsing right against the remaining budget checks the sum too.
	r, err := parseBlock(right, uint64(maxSize)-l.size)
	if err != nil {
		return nil, err
	}

	rLitLen, rLitStart := r.finalLitLen, r.finalLitStart
	if r.firstHasMatch {
		rLitLen, rLitStart = r.firstLitLen, r.firstLitStart
	}
	mergedLit := uint64(l.finalLitLen) + uint64(rLitLen)

	// Exact encoded size, computed before the allocation.
	var size uint64
	size = uint64(l.finalTok)
	size += 1 + uint64(lenExtSize(int(mergedLit))) + mergedLit
	if r.firstHasMatch {
		// Right's first match (offset and match-length extension).
		size += uint64(r.firstEnd - r.firstOffPos)
		// Right's middle sequences, copied verbatim.
		size += uint64(r.finalTok - r.firstEnd)
		// Right's final sequence, re-encoded with a zero match nibble.
		size += 1 + uint64(lenExtSize(r.finalLitLen)) + uint64(r.finalLitLen)
	}
	if size > math.MaxInt {
		return nil, lz4errors.ErrInvalidSourceShortBuffer
	}

	out = make([]byte, int(size))
	n := 0

	// Left's matches and their payload, up to its final literal-only sequence.
	n += copy(out[n:], left[:l.finalTok])

	// Boundary sequence: left's trailing literals merged with right's leading
	// ones. The length extension is recomputed from the merged total, so the
	// token of left's last sequence is never left where a decoder would read
	// it as right's offset.
	tok := 0
	if mergedLit >= 0xF {
		tok = 0xF0
	} else {
		tok = int(mergedLit) << 4
	}
	if r.firstHasMatch {
		// Right's first token keeps encoding the same match length.
		tok |= int(right[0]) & 0x0F
	}
	out[n] = byte(tok)
	n++
	if mergedLit >= 0xF {
		n = putLenExt(out, n, int(mergedLit))
	}
	n += copy(out[n:], left[l.finalLitStart:l.finalLitStart+l.finalLitLen])
	n += copy(out[n:], right[rLitStart:rLitStart+rLitLen])

	if r.firstHasMatch {
		// Offset and match-length extension, unchanged.
		n += copy(out[n:], right[r.firstOffPos:r.firstEnd])
		// Remaining sequences except the final one, unchanged.
		n += copy(out[n:], right[r.firstEnd:r.finalTok])

		// Final sequence with a normalized zero match nibble.
		if r.finalLitLen >= 0xF {
			out[n] = 0xF0
		} else {
			out[n] = byte(r.finalLitLen) << 4
		}
		n++
		if r.finalLitLen >= 0xF {
			n = putLenExt(out, n, r.finalLitLen)
		}
		n += copy(out[n:], right[r.finalLitStart:r.finalLitStart+r.finalLitLen])
	}

	if n != len(out) {
		// Unreachable given the size computation above; guard against slips.
		return nil, lz4errors.ErrInternalUnhandledState
	}
	return out, nil
}

// blockInfo records the bounded parsing state of a raw LZ4 block: the
// positions of the first and final sequences. Nothing here grows with the
// block's decompressed size.
type blockInfo struct {
	size uint64 // decompressed size

	// Final, literals-only sequence.
	finalTok      int // token position
	finalLitLen   int
	finalLitStart int // first literal byte

	// First sequence, when it contains a match (the block has more than one
	// sequence).
	firstHasMatch bool
	firstLitLen   int
	firstLitStart int
	firstOffPos   int // offset bytes position
	firstEnd      int // first byte after the match-length extension
}

// parseBlock validates src as a raw LZ4 block with no external dictionary and
// returns the positions needed to merge it. budget bounds the decompressed
// size. The strict end rule is the format's own: at least one token, a final
// literals-only sequence, and input ending exactly when its literals end; the
// final token's match nibble is ignored. Every error is detected by explicit
// checks rather than by running past a destination buffer.
func parseBlock(src []byte, budget uint64) (info blockInfo, err error) {
	if len(src) == 0 {
		return info, lz4errors.ErrInvalidSourceShortBuffer
	}
	si := 0
	var di uint64
	first := true
	for {
		if si >= len(src) {
			return info, lz4errors.ErrInvalidSourceShortBuffer
		}
		tokPos := si
		tok := src[si]
		si++

		// Literal length.
		litLen := uint64(tok >> 4)
		if litLen == 0xF {
			for {
				if si >= len(src) {
					return info, lz4errors.ErrInvalidSourceShortBuffer
				}
				x := src[si]
				si++
				if litLen > math.MaxInt64-uint64(x) {
					return info, lz4errors.ErrInvalidSourceShortBuffer
				}
				litLen += uint64(x)
				if x != 0xFF {
					break
				}
			}
		}
		// The literal bytes are part of the input, so they bound the length.
		if litLen > uint64(len(src)-si) || di+litLen > budget {
			return info, lz4errors.ErrInvalidSourceShortBuffer
		}
		litStart := si
		si += int(litLen)
		di += litLen

		if si == len(src) {
			// Final literals-only sequence. The match nibble is ignored.
			info.finalTok = tokPos
			info.finalLitLen = int(litLen)
			info.finalLitStart = litStart
			info.size = di
			return info, nil
		}

		// Offset.
		if si+2 > len(src) {
			return info, lz4errors.ErrInvalidSourceShortBuffer
		}
		offPos := si
		offset := uint64(src[si]) | uint64(src[si+1])<<8
		if offset == 0 || offset > di {
			// Zero offset, or one that reaches before this block's own data:
			// it would need an external dictionary and stays invalid after a
			// join that only shifts right to the right.
			return info, lz4errors.ErrInvalidSourceShortBuffer
		}
		si += 2

		// Match length.
		mLen := uint64(tok&0x0F) + minMatch
		if tok&0x0F == 0xF {
			for {
				if si >= len(src) {
					return info, lz4errors.ErrInvalidSourceShortBuffer
				}
				x := src[si]
				si++
				if mLen > math.MaxInt64-uint64(x) {
					return info, lz4errors.ErrInvalidSourceShortBuffer
				}
				mLen += uint64(x)
				if x != 0xFF {
					break
				}
			}
		}
		if di+mLen > budget {
			return info, lz4errors.ErrInvalidSourceShortBuffer
		}
		di += mLen

		if first {
			info.firstHasMatch = true
			info.firstLitLen = int(litLen)
			info.firstLitStart = litStart
			info.firstOffPos = offPos
			info.firstEnd = si
			first = false
		}
	}
}

// lenExtSize returns the number of LZ4 length-extension bytes used once the
// 4-bit token field is saturated at 15.
func lenExtSize(n int) int {
	if n < 0xF {
		return 0
	}
	return 1 + (n-0xF)/0xFF
}

// putLenExt writes the extension bytes of a length whose token field is 15
// and returns the position after them.
func putLenExt(b []byte, i, n int) int {
	l := n - 0xF
	for ; l >= 0xFF; l -= 0xFF {
		b[i] = 0xFF
		i++
	}
	b[i] = byte(l)
	i++
	return i
}
