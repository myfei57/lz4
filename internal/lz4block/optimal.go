package lz4block

import (
	"math/bits"
	"sync"

	"github.com/pierrec/lz4/v4/internal/lz4errors"
)

// OptimalMaxInputSize is the largest independent block CompressorOptimal
// accepts: 8KiB. Larger inputs are rejected with ErrOptimalInputTooLarge.
const OptimalMaxInputSize = 8 << 10

// OptimalMaxWorkspace is an upper bound on the scratch space a
// CompressorOptimal keeps for an OptimalMaxInputSize-byte input, in bytes,
// excluding the destination passed by the caller. Time is O(n^2).
const OptimalMaxWorkspace = 256 << 10

var (
	// Re-exported block-specific errors; see internal/lz4errors.
	ErrOptimalInputTooLarge = lz4errors.ErrOptimalInputTooLarge
	ErrOptimalShortBuffer   = lz4errors.ErrOptimalShortBuffer
)

// CompressorOptimal produces the shortest legal LZ4 block encoding of an
// independent input block, without an external dictionary. The input must be
// at most OptimalMaxInputSize bytes.
//
// Unlike the greedy compressors, every legal parse is considered with its
// real cost: token, literal and match length extensions, literal bytes and
// the two-byte offset. Shorter matches that leave a better parse later, and
// literal runs that cross an extension threshold (15, 270, ...), are both
// taken into account by a dynamic program over input positions.
//
// Incompressible input is encoded in full as literals rather than reported
// as a failure. If dst is too small for the exact optimal size,
// ErrOptimalShortBuffer is returned. Output is deterministic: the same input
// compressed on a reused or Reset compressor yields the same bytes.
//
// A CompressorOptimal is not safe for concurrent use by multiple goroutines.
type CompressorOptimal struct {
	// Reused scratch, all fully overwritten on every call.
	sa   []int32 // suffix array
	tmp  []int32 // counting-sort output, then parse records
	rank []int32 // suffix ranks, also parse records
	work []int32 // counting-sort counts, then DP costs
	lcp  []int16 // adjacent LCPs, indexed by suffix rank
	bits []uint64
	cand []int32 // chosen earlier position for the longest match at s
	ms   []int32 // match start of the best parse ending at i
	pj   []int32 // previous match end (literal start) for that parse

	optimalSize int // DP result, set by optimize
}

// Reset clears the compressor, including retained scratch space.
func (c *CompressorOptimal) Reset() { *c = CompressorOptimal{} }

var compressorOptimalPool = sync.Pool{New: func() any { return new(CompressorOptimal) }}

// CompressBlockOptimal is CompressorOptimal.CompressBlock using a pooled
// compressor.
func CompressBlockOptimal(src, dst []byte) (int, error) {
	c := compressorOptimalPool.Get().(*CompressorOptimal)
	n, err := c.CompressBlock(src, dst)
	compressorOptimalPool.Put(c)
	return n, err
}

// CompressBlock compresses src into the shortest legal LZ4 block in dst and
// returns its size. See the CompressorOptimal documentation.
func (c *CompressorOptimal) CompressBlock(src, dst []byte) (int, error) {
	n := len(src)
	if n > OptimalMaxInputSize {
		return 0, ErrOptimalInputTooLarge
	}

	c.alloc(n)

	// Every block ends with a literal-only sequence; an empty input is one
	// zero token, as the other compressors emit.
	chosen := literalCost(n)
	end := 0 // parse ends here; 0 means literal only

	if n >= 13 {
		c.buildSuffixArray(src)
		c.buildLCP(src)
		end = c.optimize(src, chosen)
		chosen = c.optimalSize // set by optimize
	}

	if len(dst) < chosen {
		return 0, ErrOptimalShortBuffer
	}
	return c.emit(src, dst, end, chosen), nil
}

// alloc grows the scratch slices to n.
func (c *CompressorOptimal) alloc(n int) {
	if cap(c.sa) < n {
		c.sa = make([]int32, n)
		c.tmp = make([]int32, n)
		c.rank = make([]int32, n)
		c.lcp = make([]int16, n)
		c.cand = make([]int32, n)
	} else {
		c.sa = c.sa[:n]
		c.tmp = c.tmp[:n]
		c.rank = c.rank[:n]
		c.lcp = c.lcp[:n]
		c.cand = c.cand[:n]
	}
	if cap(c.work) < n+1 {
		c.work = make([]int32, n+1)
		c.ms = make([]int32, n+1)
		c.pj = make([]int32, n+1)
	} else {
		c.work = c.work[:n+1]
		c.ms = c.ms[:n+1]
		c.pj = c.pj[:n+1]
	}
	words := (n + 63) >> 6
	if cap(c.bits) < words {
		c.bits = make([]uint64, words)
	} else {
		c.bits = c.bits[:words]
		for i := range c.bits {
			c.bits[i] = 0
		}
	}
}

// buildSuffixArray fills c.sa with the prefix-doubling suffix array of src and
// c.rank with suffix ranks. Both use O(n) scratch and O(n log n) time.
func (c *CompressorOptimal) buildSuffixArray(src []byte) {
	n := len(src)
	sa, rank := c.sa, c.rank

	// Initial order from the single-byte ranks.
	var freq [257]int32
	for _, b := range src {
		freq[int(b)+1]++
	}
	for i := 1; i < len(freq); i++ {
		freq[i] += freq[i-1]
	}
	for i := 0; i < n; i++ {
		b := int(src[i])
		sa[freq[b]] = int32(i)
		freq[b]++
	}
	rank[sa[0]] = 0
	classes := 1
	for i := 1; i < n; i++ {
		if src[sa[i]] != src[sa[i-1]] {
			classes++
		}
		rank[sa[i]] = int32(classes - 1)
	}

	tmp := c.tmp
	for k := 1; classes < n; k <<= 1 {
		// Suffixes ordered by their second key: those without one first,
		// then the current order shifted by k.
		p := 0
		for i := n - k; i < n; i++ {
			tmp[p] = int32(i)
			p++
		}
		for i := 0; i < n; i++ {
			if sa[i] >= int32(k) {
				tmp[p] = sa[i] - int32(k)
				p++
			}
		}

		// Stable counting sort by the first key; counts fit in classes+1.
		cnt := c.work[:classes+1]
		for i := range cnt {
			cnt[i] = 0
		}
		for i := 0; i < n; i++ {
			cnt[rank[tmp[i]]+1]++
		}
		for i := 1; i < len(cnt); i++ {
			cnt[i] += cnt[i-1]
		}
		for i := 0; i < n; i++ {
			j := tmp[i]
			r := rank[j]
			sa[cnt[r]] = j
			cnt[r]++
		}

		// New ranks from the (first, second) key pairs; tmp is dead once the
		// counting sort has finished, so it holds the new ranks temporarily.
		tmp[sa[0]] = 0
		nc := 1
		for i := 1; i < n; i++ {
			a, b := sa[i-1], sa[i]
			if rank[a] != rank[b] {
				nc++
			} else {
				a2, b2 := int32(-1), int32(-1)
				if int(a)+k < n {
					a2 = rank[a+int32(k)]
				}
				if int(b)+k < n {
					b2 = rank[b+int32(k)]
				}
				if a2 != b2 {
					nc++
				}
			}
			tmp[b] = int32(nc - 1)
		}
		copy(rank, tmp)
		classes = nc
	}
}

// buildLCP fills c.lcp using Kasai's algorithm: lcp[r] is the LCP of the
// suffixes at ranks r-1 and r, with lcp[0] = 0.
func (c *CompressorOptimal) buildLCP(src []byte) {
	n := len(src)
	sa, rank := c.sa, c.rank
	h := 0
	for s := 0; s < n; s++ {
		r := int(rank[s])
		if r == 0 {
			c.lcp[0] = 0
			continue
		}
		p := int(sa[r-1])
		for p+h < n && s+h < n && src[p+h] == src[s+h] {
			h++
		}
		c.lcp[r] = int16(h)
		if h > 0 {
			h--
		}
	}
}

// bitPrev returns the largest set rank below r in the bitset, or -1.
func bitPrev(set []uint64, r int) int {
	w, b := r>>6, uint(r&63)
	if v := set[w] & ((1 << b) - 1); v != 0 {
		return w<<6 + bits.Len64(v) - 1
	}
	for w--; w >= 0; w-- {
		if v := set[w]; v != 0 {
			return w<<6 + bits.Len64(v) - 1
		}
	}
	return -1
}

// bitNext returns the smallest set rank above r in the bitset, or -1.
func bitNext(set []uint64, r int) int {
	w, b := r>>6, uint(r&63)
	if v := set[w] &^ (^uint64(0) >> (63 - b)); v != 0 {
		return w<<6 + bits.TrailingZeros64(v)
	}
	for w++; w < len(set); w++ {
		if v := set[w]; v != 0 {
			return w<<6 + bits.TrailingZeros64(v)
		}
	}
	return -1
}

// lcpRanks returns the LCP of two suffixes given their ranks.
func (c *CompressorOptimal) lcpRanks(a, b int) int {
	if a == b {
		return len(c.sa) - int(c.sa[a])
	}
	if a > b {
		a, b = b, a
	}
	m := int(c.lcp[b])
	for r := b; r > a; r-- {
		if v := int(c.lcp[r]); v < m {
			m = v
		}
	}
	return m
}

const dpInf = 1 << 30

// optimize runs the shortest-parse dynamic program. It returns the end
// position of the last match in the best parse (0 for literals only) and
// leaves the total encoding size in c.optimalSize.
func (c *CompressorOptimal) optimize(src []byte, literalOnly int) (end int) {
	n := len(src)
	dp := c.work
	for i := range dp {
		dp[i] = dpInf
	}
	dp[0] = 0 // virtual state: literals start at 0

	best := literalOnly
	for s := 0; s <= n-12; s++ {
		// Longest match to any earlier position: the nearest inserted
		// suffix ranks on either side give the maximum LCP.
		r := int(c.rank[s])
		l, p := 0, -1
		if q := bitPrev(c.bits, r); q >= 0 {
			if v := c.lcpRanks(q, r); v > l {
				l, p = v, int(c.sa[q])
			}
		}
		if q := bitNext(c.bits, r); q >= 0 {
			if v := c.lcpRanks(r, q); v > l || v == l && int(c.sa[q]) > p {
				l, p = v, int(c.sa[q])
			}
		}
		c.bits[r>>6] |= 1 << uint(r&63)
		if l < minMatch {
			c.cand[s] = -1
			continue
		}
		c.cand[s] = int32(p)
		if d := s - p; d <= 0 || d > distanceMax {
			continue
		}

		// bc is the cheapest way to reach the literal run ending at s:
		// min over match ends j <= s of dp[j] + sequencePrefixCost(s-j).
		bc, bj := dpInf, -1
		for j := 0; j <= s; j++ {
			if dp[j] == dpInf {
				continue
			}
			if v := int(dp[j]) + sequencePrefixCost(s-j); v < bc {
				bc, bj = v, j
			}
		}
		if bj < 0 {
			continue
		}

		// Take the match at every length from 4 up to the longest one:
		// a shorter match may leave a better parse past it. Matches must
		// leave the last 5 bytes as literals.
		maxLen := l
		if max := n - 5 - s; maxLen > max {
			maxLen = max
		}
		for m := minMatch; m <= maxLen; m++ {
			i := s + m
			v := bc + 2 + matchExt(m)
			if v < int(dp[i]) {
				dp[i] = int32(v)
				c.ms[i] = int32(s)
				c.pj[i] = int32(bj)
			}
		}
	}

	for i := 1; i <= n-5; i++ {
		if dp[i] == dpInf {
			continue
		}
		if v := int(dp[i]) + literalCost(n-i); v < best {
			best = v
			end = i
		}
	}
	c.optimalSize = best
	return end
}

// emit writes the chosen parse and returns its length, which equals want.
func (c *CompressorOptimal) emit(src, dst []byte, end, want int) int {
	n := len(src)

	// Backtrack into dead SA scratch: sa=j, tmp=s for each match.
	type rec struct{ j, s, p int }
	var recs []rec
	if end > 0 {
		i := end
		for i > 0 {
			s := int(c.ms[i])
			j := int(c.pj[i])
			p := int(c.cand[s])
			recs = append(recs, rec{j, s, p})
			i = j
		}
	}

	di := 0
	pos := 0
	for k := len(recs) - 1; k >= 0; k-- {
		r := recs[k]
		next := end
		if k > 0 {
			next = recs[k-1].j
		}
		lLen := r.s - r.j
		mLen := next - r.s
		offset := r.s - r.p

		tok := byte(0)
		if lLen < 0xF {
			tok = byte(lLen << 4)
		} else {
			tok = 0xF0
		}
		if code := mLen - minMatch; code < 0xF {
			tok |= byte(code)
		} else {
			tok |= 0xF
		}
		dst[di] = tok
		di++
		if lLen >= 0xF {
			di = putExt(dst, di, lLen-0xF)
		}
		di += copy(dst[di:di+lLen], src[r.s-lLen:r.s])
		dst[di] = byte(offset)
		dst[di+1] = byte(offset >> 8)
		di += 2
		if code := mLen - minMatch; code >= 0xF {
			di = putExt(dst, di, code-0xF)
		}
		pos = next
	}

	// Final literal-only sequence.
	lLen := n - pos
	if lLen < 0xF {
		dst[di] = byte(lLen << 4)
	} else {
		dst[di] = 0xF0
	}
	di++
	if lLen >= 0xF {
		di = putExt(dst, di, lLen-0xF)
	}
	di += copy(dst[di:], src[pos:n])

	if di != want {
		// Unreachable: the DP cost is the exact encoding size.
		panic(lz4errors.ErrInternalUnhandledState)
	}
	return di
}

// putExt writes an LZ4 length extension (v already has the base subtracted)
// at dst[di:] and returns the new position.
func putExt(dst []byte, di, v int) int {
	for v >= 0xFF {
		dst[di] = 0xFF
		di++
		v -= 0xFF
	}
	dst[di] = byte(v)
	return di + 1
}

// litExt is the number of literal length extension bytes for l literals.
func litExt(l int) int {
	if l < 0xF {
		return 0
	}
	return 1 + (l-0xF)/0xFF
}

// matchExt is the number of match length extension bytes for a match of
// length m (including minMatch).
func matchExt(m int) int {
	c := m - minMatch
	if c < 0xF {
		return 0
	}
	return 1 + (c-0xF)/0xFF
}

// literalCost is the size of a standalone literal-only sequence.
func literalCost(l int) int { return 1 + litExt(l) + l }

// sequencePrefixCost is the part of a match sequence before the offset:
// token, literal length extension and literal bytes.
func sequencePrefixCost(l int) int { return 1 + litExt(l) + l }
