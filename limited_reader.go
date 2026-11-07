package lz4

import (
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/pierrec/lz4/v4/internal/lz4stream"
)

// LimitKind identifies the resource a Limit constrains.
type LimitKind uint8

const (
	// LimitSourceBytes bounds the number of compressed bytes read from the
	// underlying source, including frame and block metadata and skippable
	// frame payloads.
	LimitSourceBytes LimitKind = iota + 1
	// LimitOutputBytes bounds the number of decompressed bytes produced,
	// including bytes already decoded but not yet returned to the caller.
	LimitOutputBytes
	// LimitFrames bounds the number of frames. Skippable frames and empty
	// data frames count.
	LimitFrames
	// LimitBlocks bounds the number of data blocks. Empty raw and empty
	// compressed blocks count; the end mark does not.
	LimitBlocks
	// LimitBlockSize bounds the maximum block size a frame's descriptor is
	// allowed to declare. The check happens before any block buffer is
	// allocated.
	LimitBlockSize
)

// String names the limited resource.
func (k LimitKind) String() string {
	switch k {
	case LimitSourceBytes:
		return "source bytes"
	case LimitOutputBytes:
		return "decompressed bytes"
	case LimitFrames:
		return "frames"
	case LimitBlocks:
		return "data blocks"
	case LimitBlockSize:
		return "block size"
	}
	return "unknown limit"
}

// A Limit caps one resource to Value unsigned bytes or units. It applies
// only when On is set: a limit that is off leaves the resource unrestricted.
// A zero Value with On set genuinely forbids the resource; it never means
// "unlimited".
type Limit struct {
	On    bool
	Value uint64
}

// Limits configures the resource caps of a LimitedReader. Counters run
// across every concatenated frame in the stream and are not reset between
// frames.
type Limits struct {
	// SourceBytes caps compressed bytes read from the source. A frame that
	// is complete once the budget is spent finishes normally, as at a clean
	// stream end; needing a byte while no budget remains is an error.
	SourceBytes Limit
	// OutputBytes caps decompressed bytes produced.
	OutputBytes Limit
	// Frames caps the number of frames.
	Frames Limit
	// Blocks caps the number of data blocks.
	Blocks Limit
	// BlockMaxSize caps the block size frames may declare; 64KiB, 256KiB,
	// 1MiB, 4MiB for regular frames and 8MiB for legacy frames.
	BlockMaxSize Limit
}

// ErrLimitExceeded wraps every *LimitError: a failed budget check is an
// ordinary error, never io.EOF.
var ErrLimitExceeded = errors.New("lz4: limit exceeded")

// LimitError reports which limit was exceeded, its bound and the count that
// exceeded it. Count is the attempted cumulative total; for a block size it
// is the frame's declared maximum.
type LimitError struct {
	Kind  LimitKind
	Limit uint64
	Count uint64
}

func (e *LimitError) Error() string {
	if e.Kind == LimitBlockSize {
		return fmt.Sprintf("lz4: %s limit exceeded: frame allows %d bytes, limit is %d", e.Kind, e.Count, e.Limit)
	}
	return fmt.Sprintf("lz4: %s limit exceeded: %d of %d", e.Kind, e.Count, e.Limit)
}

// Unwrap exposes ErrLimitExceeded for errors.Is while keeping the detailed
// *LimitError available to errors.As.
func (e *LimitError) Unwrap() error { return ErrLimitExceeded }

// limitMeter is the live accounting state. Its methods implement
// lz4stream.DecodeGuard; stream events are serialized as that interface
// documents, so no locking is needed.
type limitMeter struct {
	limits Limits
	src    uint64 // compressed bytes read
	out    uint64 // decompressed bytes produced
	frames uint64 // frame magics seen
	blocks uint64 // data blocks seen
}

// add reserves n units for counter against the enabled bound l. The
// attempted total, checked for overflow, is reported in the error.
func (m *limitMeter) add(counter *uint64, n uint64, l Limit, kind LimitKind) error {
	cur := *counter
	if n > math.MaxUint64-cur {
		if l.On {
			return &LimitError{Kind: kind, Limit: l.Value, Count: math.MaxUint64}
		}
		// Keep a usable count when unlimited.
		*counter = math.MaxUint64
		return nil
	}
	total := cur + n
	if l.On && total > l.Value {
		return &LimitError{Kind: kind, Limit: l.Value, Count: total}
	}
	*counter = total
	return nil
}

func (m *limitMeter) GuardFrame(bool) error {
	return m.add(&m.frames, 1, m.limits.Frames, LimitFrames)
}

func (m *limitMeter) GuardBlock() error {
	return m.add(&m.blocks, 1, m.limits.Blocks, LimitBlocks)
}

func (m *limitMeter) GuardOutput(n int) error {
	return m.add(&m.out, uint64(n), m.limits.OutputBytes, LimitOutputBytes)
}

func (m *limitMeter) GuardBlockSize(max int) error {
	l := m.limits.BlockMaxSize
	if l.On && uint64(max) > l.Value {
		return &LimitError{Kind: LimitBlockSize, Limit: l.Value, Count: uint64(max)}
	}
	return nil
}

// GuardContentSize only rejects a declared size against the remaining output
// budget; it never mutates the output counter. The declared value comes from
// the stream, so only actual block output is counted.
func (m *limitMeter) GuardContentSize(size uint64) error {
	l := m.limits.OutputBytes
	if !l.On {
		return nil
	}
	count := m.out + size
	if size > math.MaxUint64-m.out || count > l.Value {
		if size > math.MaxUint64-m.out {
			count = math.MaxUint64
		}
		return &LimitError{Kind: LimitOutputBytes, Limit: l.Value, Count: count}
	}
	return nil
}

// accountRead adds bytes actually obtained from the underlying reader,
// saturating on overflow.
func (m *limitMeter) accountRead(n int) {
	v := uint64(n)
	if v > math.MaxUint64-m.src {
		m.src = math.MaxUint64
		return
	}
	m.src += v
}

// limitedSource caps every underlying read at the remaining source budget.
type limitedSource struct {
	r     io.Reader
	m     *limitMeter
	probe bool // the next read starts a frame: spending no budget ends the stream
}

// beginFrameProbe marks the next Read as the probe for a new frame's magic.
func (s *limitedSource) beginFrameProbe() { s.probe = true }

func (s *limitedSource) Read(p []byte) (int, error) {
	if s.probe {
		// Consumed by this single Read.
		s.probe = false
		if len(p) > 0 && s.m.limits.SourceBytes.On && s.m.src >= s.m.limits.SourceBytes.Value {
			// The stream ends exactly at the budget without another byte to
			// read. A valid frame already completed, so this is clean EOF
			// rather than a budget violation; no source is consumed.
			return 0, io.EOF
		}
	}
	if l := s.m.limits.SourceBytes; l.On && len(p) > 0 {
		if s.m.src >= l.Value {
			// At least one more byte is required; saturate at the max.
			count := l.Value + 1
			if l.Value == math.MaxUint64 {
				count = math.MaxUint64
			}
			return 0, &LimitError{Kind: LimitSourceBytes, Limit: l.Value, Count: count}
		}
		// int(remaining) is safe whenever remaining is smaller than len(p).
		if remaining := l.Value - s.m.src; uint64(len(p)) > remaining {
			p = p[:int(remaining)]
		}
	}
	n, err := s.r.Read(p)
	s.m.accountRead(n)
	return n, err
}

// LimitUsage is a snapshot of the resources a LimitedReader has consumed.
type LimitUsage struct {
	// SourceBytes is the number of compressed bytes actually read.
	SourceBytes uint64
	// OutputBytes is the number of bytes decoded, including decoded bytes
	// not yet returned.
	OutputBytes uint64
	// Frames is the number of frames seen, skippable ones included.
	Frames uint64
	// Blocks is the number of data blocks seen, empty ones included.
	Blocks uint64
}

// LimitedReader decodes an LZ4 stream while enforcing the resource caps in
// Limits. It reads and decodes no further source once a cap is exceeded, and
// the failure is a *LimitError rather than io.EOF. A LimitedReader is not
// safe for concurrent use.
type LimitedReader struct {
	r   *Reader
	m   *limitMeter
	src *limitedSource
}

// NewLimitedReader returns an LZ4 decoder that caps src according to limits.
func NewLimitedReader(src io.Reader, limits Limits) *LimitedReader {
	l := &LimitedReader{r: newReader(src, false)}
	l.configure(src, limits)
	return l
}

// configure installs a fresh meter and capped source, clears the previous
// read-ahead through Reader.Reset, and attaches the meter to the reused frame
// so it stays in force across concatenated frames.
func (l *LimitedReader) configure(src io.Reader, limits Limits) {
	m := &limitMeter{limits: limits}
	l.m = m
	l.src = &limitedSource{r: src, m: m}
	l.r.Reset(l.src)
	l.r.frame.SetGuard(m)
}

// Read implements io.Reader.
func (l *LimitedReader) Read(p []byte) (int, error) {
	return l.r.Read(p)
}

// WriteTo implements io.WriterTo; limits apply exactly as for Read.
func (l *LimitedReader) WriteTo(w io.Writer) (int64, error) {
	return l.r.WriteTo(w)
}

// Apply passes Reader options through, notably ConcurrencyOption. A
// configured concurrency level is honored by the concurrent read-ahead path,
// which reserves the budgets serially before dispatching block decoders.
func (l *LimitedReader) Apply(options ...Option) error {
	return l.r.Apply(options...)
}

// Reset stops any previous read-ahead and zeroes the counters. keepLimits
// decides whether the current Limits keep applying; with false the reader
// becomes unlimited.
func (l *LimitedReader) Reset(src io.Reader, keepLimits bool) {
	var limits Limits
	if keepLimits {
		limits = l.m.limits
	}
	l.configure(src, limits)
}

// Size returns the current frame's declared uncompressed size, like
// Reader.Size.
func (l *LimitedReader) Size() int {
	return l.r.Size()
}

// Usage returns a snapshot of the resources consumed since the last Reset.
func (l *LimitedReader) Usage() LimitUsage {
	m := l.m
	return LimitUsage{
		SourceBytes: m.src,
		OutputBytes: m.out,
		Frames:      m.frames,
		Blocks:      m.blocks,
	}
}

var _ lz4stream.DecodeGuard = (*limitMeter)(nil)
