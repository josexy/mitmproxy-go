package buf

import (
	"bytes"
	"testing"
)

func TestGenericPoolPredicate(t *testing.T) {
	created := 0
	calls := 0
	pool := NewPool(
		func() *int {
			created++
			v := created
			return &v
		},
		func(v *int) bool {
			calls++
			return *v%2 == 0
		},
	)

	first := pool.Get()
	if *first != 1 {
		t.Fatalf("first value = %d; want 1", *first)
	}
	pool.Put(first)
	if calls != 1 {
		t.Fatalf("predicate calls = %d; want 1", calls)
	}

	second := pool.Get()
	pool.Put(second)
	if calls != 2 {
		t.Fatalf("predicate calls = %d; want 2", calls)
	}
}

func TestBufferPoolResetsAcceptedBuffer(t *testing.T) {
	pool := New(8)
	b := pool.Get()
	b.WriteString("data")
	pool.Put(b)

	if b.Len() != 0 || b.Start() != 0 {
		t.Fatalf("accepted buffer was not reset: len=%d start=%d", b.Len(), b.Start())
	}
}

func TestBufferPoolRejectsOversizedBuffers(t *testing.T) {
	pool := New(8)
	b := pool.Get()
	b.TryGrow(MaxBufferSize)
	b.WriteString("data")
	pool.Put(b)

	if b.Len() == 0 {
		t.Fatalf("oversized buffer was reset, indicating it was accepted")
	}
}

func TestByteSliceAndBytesBufferPools(t *testing.T) {
	v1 := NewV1(8)
	data := v1.Get()
	(*data)[0] = 'x'
	v1.Put(data)
	if (*data)[0] != 'x' {
		t.Fatalf("fixed byte slice should not be reset")
	}

	large := make([]byte, MaxBufferSize)
	v1.Put(&large)
	if cap(large) != MaxBufferSize {
		t.Fatalf("oversized byte slice was mutated")
	}

	v2 := NewV2(8)
	b := v2.Get()
	b.WriteString("data")
	v2.Put(b)
	if b.Len() != 0 {
		t.Fatalf("bytes.Buffer was not reset")
	}

	huge := bytes.NewBuffer(make([]byte, 0, MaxBufferSize))
	huge.WriteString("data")
	v2.Put(huge)
	if huge.Len() == 0 {
		t.Fatalf("oversized bytes.Buffer was reset, indicating it was accepted")
	}
}
