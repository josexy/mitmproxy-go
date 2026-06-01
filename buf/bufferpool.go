package buf

import (
	"bytes"
	"sync"
)

const MaxBufferSize = 64 * 1024

type NewFn[T any] func() T
type PredicateFn[T any] func(T) bool

type BufferPool[T any] struct {
	pool        sync.Pool
	predicateFn PredicateFn[T]
}

func NewPool[T any](newFn NewFn[T], predicateFn PredicateFn[T]) *BufferPool[T] {
	return &BufferPool[T]{
		predicateFn: predicateFn,
		pool: sync.Pool{
			New: func() any {
				return newFn()
			},
		},
	}
}

func (bp *BufferPool[T]) Get() T {
	return bp.pool.Get().(T)
}

func (bp *BufferPool[T]) Put(buf T) {
	// we don't want to put the buffer back to the pool if the buffer size is too large
	// this is to avoid memory leak
	if bp.predicateFn != nil && !bp.predicateFn(buf) {
		return
	}
	bp.pool.Put(buf)
}

func New(initSize int) *BufferPool[*Buffer] {
	return NewPool(
		func() *Buffer { return NewSize(initSize) },
		func(buf *Buffer) bool {
			if buf.Cap() >= MaxBufferSize {
				return false
			}
			buf.Reset()
			return true
		},
	)
}

// NewV1 buffer type is []byte and the buffer size is fixed
func NewV1(initSize int) *BufferPool[[]byte] {
	return NewPool(
		func() []byte { return make([]byte, initSize) },
		func(buf []byte) bool {
			return cap(buf) < MaxBufferSize
		},
	)
}

// NewV2 buffer type is *bytes.Buffer and the buffer size is variable
func NewV2(initSize int) *BufferPool[*bytes.Buffer] {
	return NewPool(
		func() *bytes.Buffer { return bytes.NewBuffer(make([]byte, 0, initSize)) },
		func(buf *bytes.Buffer) bool {
			if buf.Cap() >= MaxBufferSize {
				return false
			}
			buf.Reset()
			return true
		},
	)
}
