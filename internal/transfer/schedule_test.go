package transfer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"testing"
	"testing/iotest"
)

func TestPartSizeSchedule(t *testing.T) {
	const (
		MiB = int64(1) << 20
		GiB = 1 << 30
		TiB = int64(1) << 40
	)
	for _, c := range []struct {
		size     int64
		partSize int64
		parts    int
		last     int64
	}{
		{0, 8 * MiB, 0, 0},
		{3, 8 * MiB, 1, 3},
		{100 * MiB, 8 * MiB, 13, 4 * MiB},
		{4 * GiB, 8 * MiB, 512, 8 * MiB},
		{4*GiB + 1, 8 * MiB, 513, 1},
		{80 * GiB, 16 * MiB, 5120, 16 * MiB},
		{500 * GiB, 64 * MiB, 8000, 64 * MiB},
		{TiB, 64 * MiB, 16384, 64 * MiB},
		{4 * TiB, 64 * MiB, 65536, 64 * MiB},
	} {
		ps := PartSize(c.size)
		n := PartCount(c.size, ps)
		if ps != c.partSize || n != c.parts {
			t.Errorf("size %d: part size %d and %d parts, want %d and %d", c.size, ps, n, c.partSize, c.parts)
			continue
		}
		if n > 0 {
			if last := partLen(c.size, ps, n); last != c.last {
				t.Errorf("size %d: last part %d bytes, want %d", c.size, last, c.last)
			}
		}
	}
}

func TestCompositeVectors(t *testing.T) {
	if got := Composite(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty: %s", got)
	}
	if got := Composite([][sha256.Size]byte{sha256.Sum256([]byte("abc"))}); got != "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358" {
		t.Errorf("abc: %s", got)
	}
	f := file{data: make([]byte, 1000), partSize: 256}
	for i := range f.data {
		f.data[i] = byte(i % 251)
	}
	want := []string{
		"5bc31b283cef0072274e97d74916552954c935794536cab632641e5ea071379d",
		"e0e30ecceaaf032ca8e25ea5fdce903102fd4caa94d7c904328384b087bdfb89",
		"ea2d6f71c357e4855c9a53451aaeb2ca4121b33fa8053db6262b394e0170c879",
		"3dc20cab24c0299c39cf7074506dd411eccfa09ece5fe8eab0ddd8acf89b2dc5",
	}
	for n := 1; n <= 4; n++ {
		if got := f.sum(n); got != want[n-1] {
			t.Errorf("part %d: %s", n, got)
		}
	}
	if got := f.composite(); got != "e6cec81163d2e289742636ba3b36a7b799773a56971c086fcd851aee99ccac17" {
		t.Errorf("1,000 bytes in parts of 256: %s", got)
	}
}

func TestIDsAndKeys(t *testing.T) {
	if id := newID(); !ValidID(id) {
		t.Errorf("new ID %q is not valid", id)
	}
	for _, bad := range []string{"", "0123456789abcdef0123456789abcde", "0123456789ABCDEF0123456789abcdef", "../../../../etc/passwd/0123456789a", "0123456789abcdef0123456789abcdeg"} {
		if ValidID(bad) {
			t.Errorf("ValidID(%q)", bad)
		}
	}
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	for k, ok := range map[string]bool{"": true, "a-Z_9": true, string(long[:128]): true, string(long): false, "a b": false, "ä": false, "a/b": false} {
		if validClientKey(k) != ok {
			t.Errorf("validClientKey(%q) = %v", k, !ok)
		}
	}
}

func TestPartHashesBeyondTheFirstChunk(t *testing.T) {
	s := newSession(Record{ID: "x", Size: 2050, PartSize: 1, PartCount: 2050})
	hs := map[int][sha256.Size]byte{}
	for _, n := range []int{1, hashChunk, hashChunk + 1, 2050} {
		hs[n] = sha256.Sum256([]byte{byte(n), byte(n >> 8)})
		s.keep(n, hs[n])
	}
	for n, h := range hs {
		if !s.has(n) || s.hash(n) != h {
			t.Errorf("part %d: has %v, hash %x", n, s.has(n), s.hash(n))
		}
	}
	if s.has(2) || s.has(2049) || len(s.chunks) != 3 || s.chunks[1] == nil || s.chunks[0] == s.chunks[1] {
		t.Errorf("chunks %d", len(s.chunks))
	}
	want := []Range{{1, 1}, {hashChunk, hashChunk + 1}, {2050, 2050}}
	if got := s.ranges(false); !slices.Equal(got, want) {
		t.Errorf("ranges %v", got)
	}
}

func TestTheCompositeOfAStoredFile(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	for _, c := range []struct {
		data     []byte
		partSize int64
		want     string
		parts    int64
	}{
		{nil, 8 << 20, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0},
		{[]byte("abc"), 8 << 20, "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358", 1},
		{data, 256, "e6cec81163d2e289742636ba3b36a7b799773a56971c086fcd851aee99ccac17", 4},
		{data[:768], 256, Composite([][sha256.Size]byte{sha256.Sum256(data[:256]), sha256.Sum256(data[256:512]), sha256.Sum256(data[512:768])}), 3},
		{[]byte("abc"), 1, Composite([][sha256.Size]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b")), sha256.Sum256([]byte("c"))}), 3},
	} {
		got, n, err := CompositeOf(iotest.OneByteReader(bytes.NewReader(c.data)), c.partSize)
		if err != nil || got != c.want || n != c.parts {
			t.Errorf("%d bytes in parts of %d: %s, %d parts, %v; want %s, %d", len(c.data), c.partSize, got, n, err, c.want, c.parts)
		}
	}
	for _, ps := range []int64{0, -1} {
		if _, _, err := CompositeOf(bytes.NewReader(data), ps); err == nil {
			t.Errorf("part size %d accepted", ps)
		}
	}
	broken := errors.New("broken")
	if _, _, err := CompositeOf(io.MultiReader(bytes.NewReader(data), iotest.ErrReader(broken)), 256); !errors.Is(err, broken) {
		t.Errorf("a failed read: %v", err)
	}
}

func TestThePartSizesTheServerUses(t *testing.T) {
	for n, want := range map[int64]bool{
		8 << 20: true, 16 << 20: true, 32 << 20: true, 64 << 20: true,
		0: false, 1: false, 8<<20 - 1: false, 8<<20 + 1: false, 4 << 20: false, 128 << 20: false, 24 << 20: false, -8 << 20: false,
	} {
		if got := IsPartSize(n); got != want {
			t.Errorf("IsPartSize(%d) = %v", n, got)
		}
	}
	for size := int64(1); size < 1<<46; size *= 3 {
		if ps := PartSize(size); !IsPartSize(ps) {
			t.Errorf("the schedule gives %d bytes a part size of %d, which IsPartSize refuses", size, ps)
		}
	}
}
