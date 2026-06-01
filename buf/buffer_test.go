package buf

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

type limitedWriter struct {
	limit int
	bytes.Buffer
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

type errorWriter struct {
	n int
}

func (w errorWriter) Write(p []byte) (int, error) {
	if len(p) < w.n {
		return len(p), errors.New("write failed")
	}
	return w.n, errors.New("write failed")
}

func TestBufferWriteReadAndString(t *testing.T) {
	b := NewSize(0)
	if !b.IsEmpty() || b.String() != "" {
		t.Fatalf("new zero buffer should be empty")
	}

	if n, err := b.WriteString("hello"); err != nil || n != 5 {
		t.Fatalf("WriteString = %d, %v; want 5, nil", n, err)
	}
	if err := b.WriteByte(' '); err != nil {
		t.Fatalf("WriteByte: %v", err)
	}
	if n, err := b.WriteRune('世'); err != nil || n != utf8.RuneLen('世') {
		t.Fatalf("WriteRune = %d, %v; want rune len, nil", n, err)
	}
	if n, err := b.Write([]byte("界")); err != nil || n != len("界") {
		t.Fatalf("Write = %d, %v; want %d, nil", n, err, len("界"))
	}

	if got, want := b.String(), "hello 世界"; got != want {
		t.Fatalf("String() = %q; want %q", got, want)
	}
	if got := b.Byte(0); got != 'h' {
		t.Fatalf("Byte(0) = %q; want h", got)
	}
	b.SetByte(0, 'H')
	if got, want := string(b.Bytes()), "Hello 世界"; got != want {
		t.Fatalf("SetByte result = %q; want %q", got, want)
	}

	c, err := b.ReadByte()
	if err != nil || c != 'H' {
		t.Fatalf("ReadByte = %q, %v; want H, nil", c, err)
	}
	part, err := b.ReadBytes(5)
	if err != nil || string(part) != "ello " {
		t.Fatalf("ReadBytes = %q, %v; want %q, nil", part, err, "ello ")
	}
	r, size, err := b.ReadRune()
	if err != nil || r != '世' || size != utf8.RuneLen('世') {
		t.Fatalf("ReadRune = %q, %d, %v; want 世, %d, nil", r, size, err, utf8.RuneLen('世'))
	}
	buf := make([]byte, len("界"))
	n, err := b.Read(buf)
	if err != nil || n != len("界") || string(buf) != "界" {
		t.Fatalf("Read = %d, %v, %q; want full 界", n, err, buf)
	}
	if _, err := b.ReadByte(); err != io.EOF {
		t.Fatalf("empty ReadByte err = %v; want EOF", err)
	}
	if _, _, err := b.ReadRune(); err != io.EOF {
		t.Fatalf("empty ReadRune err = %v; want EOF", err)
	}
}

func TestBufferReadHelpers(t *testing.T) {
	b := NewSize(8)
	n, err := b.ReadAtLeast(strings.NewReader("abc"), 2)
	if err != nil || n != 3 || string(b.Bytes()) != "abc" {
		t.Fatalf("ReadAtLeast = %d, %v, %q; want 3, nil, abc", n, err, b.Bytes())
	}

	if _, err := b.ReadAtLeast(strings.NewReader("x"), 10); err != io.ErrShortBuffer {
		t.Fatalf("ReadAtLeast oversized err = %v; want ErrShortBuffer", err)
	}

	b.Reset()
	nn, err := b.ReadFull(strings.NewReader("xy"), 2)
	if err != nil || nn != 2 || string(b.Bytes()) != "xy" {
		t.Fatalf("ReadFull = %d, %v, %q; want 2, nil, xy", nn, err, b.Bytes())
	}
	if _, err := b.ReadFull(strings.NewReader("toolong"), b.Cap()+1); err != io.ErrShortBuffer {
		t.Fatalf("ReadFull oversized err = %v; want ErrShortBuffer", err)
	}

	b = NewSize(0)
	n, err = b.ReadFrom(strings.NewReader(strings.Repeat("a", ReadSize+1)))
	if err != nil || n != ReadSize+1 || b.Len() != ReadSize+1 {
		t.Fatalf("ReadFrom = %d, %v, len %d; want %d, nil", n, err, b.Len(), ReadSize+1)
	}
}

func TestBufferWriteTo(t *testing.T) {
	b := As([]byte("hello"))
	var dst bytes.Buffer
	n, err := b.WriteTo(&dst)
	if err != nil || n != 5 || dst.String() != "hello" || !b.IsEmpty() {
		t.Fatalf("WriteTo = %d, %v, dst %q, empty %v; want full write and reset", n, err, dst.String(), b.IsEmpty())
	}

	b = As([]byte("hello"))
	sw := &limitedWriter{limit: 2}
	n, err = b.WriteTo(sw)
	if err != io.ErrShortWrite || n != 2 || sw.String() != "he" {
		t.Fatalf("short WriteTo = %d, %v, %q; want 2, ErrShortWrite, he", n, err, sw.String())
	}

	b = As([]byte("hello"))
	n, err = b.WriteTo(errorWriter{n: 3})
	if err == nil || n != 3 {
		t.Fatalf("error WriteTo = %d, %v; want partial count and error", n, err)
	}
}

func TestBufferViewAndClone(t *testing.T) {
	b := As([]byte("abcdef"))
	b.Advance(2)
	b.Truncate(3)
	if got, want := b.Start(), 2; got != want {
		t.Fatalf("Start() = %d; want %d", got, want)
	}
	if got, want := string(b.Bytes()), "cde"; got != want {
		t.Fatalf("Bytes() = %q; want %q", got, want)
	}
	if got, want := string(b.Slice(-10, 99)), "cde"; got != want {
		t.Fatalf("clamped Slice = %q; want %q", got, want)
	}
	if got := len(b.Index(1)); got != 0 {
		t.Fatalf("Index returns len %d; want zero-length slice", got)
	}

	clone := b.Clone()
	clone.SetByte(0, 'X')
	if got, want := string(clone.Bytes()), "Xde"; got != want {
		t.Fatalf("clone bytes = %q; want %q", got, want)
	}
	if got, want := string(b.Bytes()), "cde"; got != want {
		t.Fatalf("original after clone mutation = %q; want %q", got, want)
	}

	b.Resize(1, 2)
	if got, want := string(b.Bytes()), "bc"; got != want {
		t.Fatalf("Resize bytes = %q; want %q", got, want)
	}
}

func TestBufferPanics(t *testing.T) {
	t.Run("negative grow", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatalf("TryGrow(-1) did not panic")
			}
		}()
		NewSize(0).TryGrow(-1)
	})

	t.Run("invalid rune", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatalf("WriteRune(invalid) did not panic")
			}
		}()
		_, _ = NewSize(0).WriteRune(utf8.RuneError + 0x110000)
	})
}

func TestNilBufferString(t *testing.T) {
	var b *Buffer
	if got, want := b.String(), "<nil>"; got != want {
		t.Fatalf("nil String() = %q; want %q", got, want)
	}
}
