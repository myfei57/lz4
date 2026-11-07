package lz4block

import (
	"math"

	"github.com/pierrec/lz4/v4/internal/lz4errors"
)

// DecodeBlockLen returns the exact number of bytes the LZ4 block src
// decompresses to, without decompressing it. It walks the block sequences
// and rejects the blocks a decoder rejects while reading them: length fields
// or literals that run past src, a zero or out-of-range match offset, a
// length that does not fit a machine int, and totals that overflow. A match
// offset may reference the dictLen bytes preceding the block, as the decoder
// does with a dictionary.
//
// Match contents are not inspected: a nil error and length n mean the block
// is structurally able to produce n bytes, not that the bytes are correct.
// An empty block decodes to zero bytes.
func DecodeBlockLen(src []byte, dictLen int) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}
	si, sn := 0, len(src)
	var out uint64
	for {
		if si >= sn {
			return 0, lz4errors.ErrInvalidSourceShortBuffer
		}
		token := src[si]
		si++

		// Literal length.
		litLen := uint64(token >> 4)
		if litLen == 0xF {
			for {
				if si >= sn {
					return 0, lz4errors.ErrInvalidSourceShortBuffer
				}
				x := src[si]
				si++
				litLen += uint64(x)
				if litLen > math.MaxInt {
					return 0, lz4errors.ErrInvalidSourceShortBuffer
				}
				if x != 0xFF {
					break
				}
			}
		}
		if litLen > uint64(sn-si) {
			return 0, lz4errors.ErrInvalidSourceShortBuffer
		}
		si += int(litLen)
		if out > math.MaxUint64-litLen {
			return 0, lz4errors.ErrInvalidSourceShortBuffer
		}
		out += litLen

		mLen := uint64(token & 0x0F)
		if si == sn {
			// A block ends with literals only; the low token nibble must
			// then be zero, mirroring the decoder's end test.
			if mLen != 0 {
				return 0, lz4errors.ErrInvalidSourceShortBuffer
			}
			break
		}
		// Match offset and length.
		if si+2 > sn {
			return 0, lz4errors.ErrInvalidSourceShortBuffer
		}
		offset := uint64(src[si]) | uint64(src[si+1])<<8
		si += 2
		if offset == 0 || offset > out+uint64(dictLen) {
			return 0, lz4errors.ErrInvalidSourceShortBuffer
		}
		mLen += minMatch
		if token&0x0F == 0x0F {
			for {
				if si >= sn {
					return 0, lz4errors.ErrInvalidSourceShortBuffer
				}
				x := src[si]
				si++
				mLen += uint64(x)
				if mLen > math.MaxInt {
					return 0, lz4errors.ErrInvalidSourceShortBuffer
				}
				if x != 0xFF {
					break
				}
			}
		}
		if out > math.MaxUint64-mLen {
			return 0, lz4errors.ErrInvalidSourceShortBuffer
		}
		out += mLen
		if si == sn {
			// The decoder tolerates a block ending with its last match,
			// in which case the final literals are empty.
			break
		}
	}
	if out > math.MaxInt {
		return 0, lz4errors.ErrInvalidSourceShortBuffer
	}
	return int(out), nil
}
