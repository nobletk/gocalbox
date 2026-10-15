package state

import (
	"maps"
	"testing"
	"time"
)

func keys(t *testing.T, d *DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	d.View(func(tx *Tx) error {
		return tx.tx.Bucket(bucketUploaders).ForEach(func(k, v []byte) error {
			var u Uploader
			if r, ok, err := tx.Uploader(string(k)); err != nil || !ok {
				t.Errorf("record %s: %v", k, err)
			} else {
				u = r
			}
			out[string(k)] = u.User
			return nil
		})
	})
	return out
}

func put(t *testing.T, d *DB, records map[string]string) {
	t.Helper()
	err := d.Update(func(tx *Tx) error {
		for p, user := range records {
			if err := tx.PutUploader(p, Uploader{User: user, Created: time.Now().UTC()}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUploaderRecords(t *testing.T) {
	d, _ := openTemp(t)
	size, mtime := int64(5), int64(1_700_000_000_123_456_789)
	rec := Uploader{User: "u-1", Created: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC), Size: &size, MTime: &mtime}
	if err := d.Update(func(tx *Tx) error { return tx.PutUploader("a/b.txt", rec) }); err != nil {
		t.Fatal(err)
	}
	d.View(func(tx *Tx) error {
		got, ok, err := tx.Uploader("a/b.txt")
		if err != nil || !ok || got.User != "u-1" || *got.Size != 5 || *got.MTime != mtime || !got.Created.Equal(rec.Created) {
			t.Errorf("Uploader = %+v, %v, %v", got, ok, err)
		}
		if _, ok, err := tx.Uploader("a/B.txt"); ok || err != nil {
			t.Error("a record found under another spelling")
		}
		return nil
	})
	for _, p := range []string{"", ".", "/a", "a/"} {
		if err := d.Update(func(tx *Tx) error { return tx.PutUploader(p, rec) }); err == nil {
			t.Errorf("record at %q accepted", p)
		}
	}
	if err := d.Update(func(tx *Tx) error { return tx.PutUploader("x", Uploader{}) }); err == nil {
		t.Error("a record without a user was accepted")
	}
}

func TestUploaderRangesStopAtTheFolder(t *testing.T) {
	d, _ := openTemp(t)
	put(t, d, map[string]string{
		"a/b": "u1", "a/b/c": "u1", "a/b/c/d": "u1", "a/b!x": "u2", "a/b.txt": "u2", "a/bc": "u2", "a/bc/x": "u2", "a": "u3",
		"z/b": "stale", "z/b/old": "stale", "z/bc": "keep",
	})
	if err := d.Update(func(tx *Tx) error { return tx.MoveUploaders("a/b", "z/b") }); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"z/b": "u1", "z/b/c": "u1", "z/b/c/d": "u1", "a/b!x": "u2", "a/b.txt": "u2", "a/bc": "u2", "a/bc/x": "u2", "a": "u3", "z/bc": "keep",
	}
	if got := keys(t, d); !maps.Equal(got, want) {
		t.Errorf("after the move: %v", got)
	}
	if err := d.Update(func(tx *Tx) error { return tx.DeleteUploaders("a/bc") }); err != nil {
		t.Fatal(err)
	}
	delete(want, "a/bc")
	delete(want, "a/bc/x")
	if got := keys(t, d); !maps.Equal(got, want) {
		t.Errorf("after the delete: %v", got)
	}
	for _, bad := range [][2]string{{"z/b", "z/b/c/e"}, {"z/b", "z/b"}, {".", "q"}} {
		if err := d.Update(func(tx *Tx) error { return tx.MoveUploaders(bad[0], bad[1]) }); err == nil {
			t.Errorf("MoveUploaders(%q, %q) accepted", bad[0], bad[1])
		}
	}
	if err := d.Update(func(tx *Tx) error { return tx.MoveUploaders("nothing/here", "q") }); err != nil {
		t.Errorf("moving no records: %v", err)
	}
	if err := d.Update(func(tx *Tx) error { return tx.DeleteUploader("z/b") }); err != nil {
		t.Fatal(err)
	}
	delete(want, "z/b")
	if got := keys(t, d); !maps.Equal(got, want) {
		t.Errorf("after deleting one record: %v", got)
	}
}
