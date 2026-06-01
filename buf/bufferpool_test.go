package buf

import (
	"bytes"
	"testing"
)

func TestGenericPoolPredicate(t *testing.T) {
	created := 0
	pool := NewPool(
		func() *int {
			created++
			v := created
			return &v
		},
		func(v *int) bool { return *v%2 == 0 },
	)

	first := pool.Get()
	if *first != 1 {
		t.Fatalf("first value = %d; want 1", *first)
	}
	pool.Put(first)
	second := pool.Get()
	if *second != 2 {
		t.Fatalf("rejected value should not be reused, got %d; want 2", *second)
	}
	pool.Put(second)
	third := pool.Get()
	if third != second {
		t.Fatalf("accepted value was not reused")
	}
}

func TestBufferPoolResetsAcceptedBuffer(t *testing.T) {
	pool := New(8)
	b := pool.Get()
	b.WriteString("data")
	pool.Put(b)

	got := pool.Get()
	if got.Len() != 0 || got.Start() != 0 {
		t.Fatalf("pooled buffer was not reset: len=%d start=%d", got.Len(), got.Start())
	}
}

func TestBufferPoolRejectsOversizedBuffers(t *testing.T) {
	pool := New(8)
	b := pool.Get()
	b.TryGrow(MaxBufferSize)
	pool.Put(b)

	got := pool.Get()
	if got == b {
		t.Fatalf("oversized buffer was returned to pool")
	}
	if got.Cap() >= MaxBufferSize {
		t.Fatalf("new pooled buffer cap = %d; want smaller than MaxBufferSize", got.Cap())
	}
}

func TestByteSliceAndBytesBufferPools(t *testing.T) {
	v1 := NewV1(8)
	data := v1.Get()
	(*data)[0] = 'x'
	v1.Put(data)
	if got := v1.Get(); got != data {
		t.Fatalf("fixed byte slice should be reused")
	}

	large := make([]byte, MaxBufferSize)
	v1.Put(&large)
	if got := v1.Get(); cap(*got) >= MaxBufferSize {
		t.Fatalf("oversized byte slice was reused")
	}

	v2 := NewV2(8)
	b := v2.Get()
	b.WriteString("data")
	v2.Put(b)
	got := v2.Get()
	if got != b || got.Len() != 0 {
		t.Fatalf("bytes.Buffer was not reset and reused")
	}

	huge := bytes.NewBuffer(make([]byte, 0, MaxBufferSize))
	v2.Put(huge)
	if got := v2.Get(); got == huge {
		t.Fatalf("oversized bytes.Buffer was returned to pool")
	}
}
