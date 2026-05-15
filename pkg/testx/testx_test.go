package testx_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/testx"
)

func TestReader(t *testing.T) {
	t.Run("EOF", func(t *testing.T) {
		t.Run("empty input returns EOF", func(t *testing.T) {
			reader := testx.NewReader(nil, nil)
			p := make([]byte, 1)
			n, err := reader.Read(p)
			require.ErrorIs(t, err, io.EOF)
			require.Zero(t, n)
		})
		t.Run("partial reads eventually return EOF", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), nil)
			p := make([]byte, 3)
			n, err := reader.Read(p)
			require.NoError(t, err)
			require.Equal(t, 3, n)
			testx.EqualSlice(t, []byte("hel"), p[:n])
			n, err = reader.Read(p)
			require.NoError(t, err)
			require.Equal(t, 2, n)
			testx.EqualSlice(t, []byte("lo"), p[:n])
			n, err = reader.Read(p)
			require.ErrorIs(t, err, io.EOF)
			require.Zero(t, n)
		})
	})
	t.Run("trailing error", func(t *testing.T) {
		t.Run("empty input returns trailing error", func(t *testing.T) {
			reader := testx.NewReader(nil, testx.ErrReadFailure)
			p := make([]byte, 1)
			n, err := reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Zero(t, n)
		})
		t.Run("final read returns data plus trailing error", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), testx.ErrReadFailure)
			p := make([]byte, 3)
			n, err := reader.Read(p)
			require.NoError(t, err)
			require.Equal(t, 3, n)
			testx.EqualSlice(t, []byte("hel"), p[:n])
			n, err = reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Equal(t, 2, n)
			testx.EqualSlice(t, []byte("lo"), p[:n])
		})
		t.Run("repeated reads keep returning trailing error", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), testx.ErrReadFailure)
			p := make([]byte, 6)
			n, err := reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Equal(t, 5, n)
			testx.EqualSlice(t, []byte("hello"), p[:n])
			n, err = reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Zero(t, n)
		})
	})
	t.Run("zero length read", func(t *testing.T) {
		t.Run("before EOF returns no data and no error", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), nil)
			p := make([]byte, 0)
			n, err := reader.Read(p)
			require.NoError(t, err)
			require.Zero(t, n)
			p = make([]byte, 5)
			n, err = reader.Read(p)
			require.NoError(t, err)
			require.Equal(t, 5, n)
			testx.EqualSlice(t, []byte("hello"), p[:n])
		})
		t.Run("before EOF does not suppress trailing error", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), testx.ErrReadFailure)
			p := make([]byte, 0)
			n, err := reader.Read(p)
			require.NoError(t, err)
			require.Zero(t, n)
			p = make([]byte, 5)
			n, err = reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Equal(t, 5, n)
			testx.EqualSlice(t, []byte("hello"), p[:n])
		})
		t.Run("at EOF returns EOF without trailing error", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), nil)
			p := make([]byte, 5)
			n, err := reader.Read(p)
			require.NoError(t, err)
			require.Equal(t, 5, n)
			testx.EqualSlice(t, []byte("hello"), p[:n])
			p = make([]byte, 0)
			n, err = reader.Read(p)
			require.ErrorIs(t, err, io.EOF)
			require.Zero(t, n)
		})
		t.Run("at EOF returns trailing error", func(t *testing.T) {
			reader := testx.NewReader([]byte("hello"), testx.ErrReadFailure)
			p := make([]byte, 5)
			n, err := reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Equal(t, 5, n)
			testx.EqualSlice(t, []byte("hello"), p[:n])
			p = make([]byte, 0)
			n, err = reader.Read(p)
			require.ErrorIs(t, err, testx.ErrReadFailure)
			require.Zero(t, n)
		})
	})
	t.Run("new reader does not copy input", func(t *testing.T) {
		b := []byte("hello")
		reader := testx.NewReader(b, nil)
		b[0] = 'x'
		p := make([]byte, 5)
		n, err := reader.Read(p)
		require.NoError(t, err)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("xello"), p[:n])
	})
}

func TestWriterWrite(t *testing.T) {
	t.Run("appends each payload without error", func(t *testing.T) {
		writer := testx.NewWriter(nil)
		n, err := writer.Write([]byte("hello"))
		require.NoError(t, err)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("hello"), writer.Bytes())
		require.Equal(t, "hello", writer.String())
		n, err = writer.Write([]byte("world"))
		require.NoError(t, err)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("helloworld"), writer.Bytes())
		require.Equal(t, "helloworld", writer.String())
	})
	t.Run("returns configured error and records latest payload", func(t *testing.T) {
		writer := testx.NewWriter(testx.ErrWriteFailure)
		n, err := writer.Write([]byte("hello"))
		require.ErrorIs(t, err, testx.ErrWriteFailure)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("hello"), writer.Bytes())
		require.Equal(t, "hello", writer.String())
		n, err = writer.Write([]byte("world"))
		require.ErrorIs(t, err, testx.ErrWriteFailure)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("world"), writer.Bytes())
		require.Equal(t, "world", writer.String())
	})
}

func TestWriterWriteString(t *testing.T) {
	t.Run("appends each payload without error", func(t *testing.T) {
		writer := testx.NewWriter(nil)
		n, err := writer.WriteString("hello")
		require.NoError(t, err)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("hello"), writer.Bytes())
		require.Equal(t, "hello", writer.String())
		n, err = writer.WriteString("world")
		require.NoError(t, err)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("helloworld"), writer.Bytes())
		require.Equal(t, "helloworld", writer.String())
	})
	t.Run("returns configured error and records latest payload", func(t *testing.T) {
		writer := testx.NewWriter(testx.ErrWriteFailure)
		n, err := writer.WriteString("hello")
		require.ErrorIs(t, err, testx.ErrWriteFailure)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("hello"), writer.Bytes())
		require.Equal(t, "hello", writer.String())
		n, err = writer.WriteString("world")
		require.ErrorIs(t, err, testx.ErrWriteFailure)
		require.Equal(t, 5, n)
		testx.EqualSlice(t, []byte("world"), writer.Bytes())
		require.Equal(t, "world", writer.String())
	})
}

func TestEqualSlice(t *testing.T) {
	t.Run("nil equals nil", func(t *testing.T) {
		testx.EqualSlice(t, []byte(nil), []byte(nil))
	})
	t.Run("nil equals empty", func(t *testing.T) {
		testx.EqualSlice(t, []byte(nil), []byte{})
	})
	t.Run("empty equals nil", func(t *testing.T) {
		testx.EqualSlice(t, []byte{}, []byte(nil))
	})
	t.Run("empty equals empty", func(t *testing.T) {
		testx.EqualSlice(t, []byte{}, []byte{})
	})
	t.Run("byte slice", func(t *testing.T) {
		testx.EqualSlice(t, []byte("Hello, world!"), []byte("Hello, world!"))
	})
	t.Run("string slice", func(t *testing.T) {
		testx.EqualSlice(t, []string{"a", "b", "c"}, []string{"a", "b", "c"})
	})
	t.Run("int slice", func(t *testing.T) {
		testx.EqualSlice(t, []int{1, 2, 3}, []int{1, 2, 3})
	})
}

func TestStub(t *testing.T) {
	target := "target"
	t.Cleanup(func() {
		require.Equal(t, "target", target)
	})
	testx.Stub(t, &target, "double")
	require.Equal(t, "double", target)
}
