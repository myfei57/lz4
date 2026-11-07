package lz4stream

// DecodeGuard limits the resources consumed while decoding untrusted
// streams. A Frame with no guard (the zero value) is unlimited.
//
// Calls are serialized: frame and block-size events run while a frame
// header is parsed, and block and output events from the single goroutine
// that reads blocks (in concurrent mode, the read-ahead loop), before any
// worker decodes the block. Implementations need no locking, and an error
// stops the stream without consuming further source.
type DecodeGuard interface {
	// GuardFrame accounts one frame magic: a skippable frame when
	// skippable is true (its payload has already been read), or a data
	// frame otherwise. Empty frames and skippable frames count.
	GuardFrame(skippable bool) error

	// GuardBlockSize is called with the frame's declared maximum block
	// size, after its descriptor is parsed and before any block buffer is
	// allocated. It is called once per data frame, including concatenated
	// legacy ones.
	GuardBlockSize(max int) error

	// GuardBlock accounts one data block, including empty raw and empty
	// compressed blocks, after its size field is read and before its data.
	// The end mark is not a block.
	GuardBlock() error

	// GuardContentSize is called with the frame's declared content size
	// when its descriptor carries one. It may reject a declared size early
	// but cannot replace counting the bytes the blocks actually produce.
	GuardContentSize(size uint64) error

	// GuardOutput reserves the exact n bytes a block decodes to, before
	// they are produced: for raw blocks before the payload is read, and for
	// compressed blocks after the payload is measured but before it is
	// decoded. n already includes bytes that stay buffered instead of being
	// handed to the caller immediately.
	GuardOutput(n int) error
}

// SetGuard installs g as the frame's resource guard; it survives Reset so
// that counters stay shared across concatenated frames read with the Frame.
// Pass nil to remove it.
func (f *Frame) SetGuard(g DecodeGuard) {
	f.guard = g
}

// Guard returns the installed resource guard, or nil.
func (f *Frame) Guard() DecodeGuard {
	return f.guard
}
