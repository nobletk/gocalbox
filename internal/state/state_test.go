package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, path
}

func newUser(name string, role Role) User {
	return User{ID: NewUserID(), Username: name, Role: role, Hash: "$argon2id$secret", CreatedAt: time.Now().UTC(), CreatedBy: "console"}
}

func TestOpenCreatesSchemaAndDeviceKey(t *testing.T) {
	d, path := openTemp(t)
	var key []byte
	d.View(func(tx *Tx) error { key = tx.DeviceKey(); return nil })
	if len(key) != 32 {
		t.Fatalf("device key of %d bytes", len(key))
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, %v", fi.Mode(), err)
		}
	}
	d.Close()

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	var key2 []byte
	again.View(func(tx *Tx) error { key2 = tx.DeviceKey(); return nil })
	if !bytes.Equal(key, key2) {
		t.Error("the device key changed on reopening")
	}
}

func TestOpenFailsFastWhileLocked(t *testing.T) {
	_, path := openTemp(t)
	start := time.Now()
	_, err := Open(path)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestOpenRefusesOtherSchemasAndFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	d.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(keySchema, []byte("2")) })
	d.Close()
	var se *SchemaError
	if _, err := Open(path); !errors.As(err, &se) || se.Found != 2 || !strings.Contains(err.Error(), "newer") {
		t.Errorf("newer schema: %v", err)
	}

	other := filepath.Join(t.TempDir(), "other.db")
	b, _ := bolt.Open(other, 0o600, nil)
	b.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte("things")); return err })
	b.Close()
	if _, err := Open(other); !errors.Is(err, ErrNotStateFile) {
		t.Errorf("foreign bbolt file: %v", err)
	}

	older := filepath.Join(t.TempDir(), "older.db")
	if d, err = Open(older); err != nil {
		t.Fatal(err)
	}
	d.bolt.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketMeta).Put(keySchema, []byte("0")) })
	d.Close()
	if _, err := Open(older); !errors.As(err, &se) || se.Found != 0 || !strings.Contains(err.Error(), "no migration") {
		t.Errorf("older schema: %v", err)
	}

	text := filepath.Join(t.TempDir(), "text.db")
	os.WriteFile(text, bytes.Repeat([]byte("not a database "), 1000), 0o600)
	if _, err := Open(text); !errors.Is(err, ErrNotStateFile) {
		t.Errorf("text file: %v", err)
	}
}

func TestUsers(t *testing.T) {
	d, _ := openTemp(t)
	bob, alice := newUser("bob", RoleContributor), newUser("alice", RoleAdmin)
	err := d.Update(func(tx *Tx) error {
		if err := tx.CreateUser(bob); err != nil {
			return err
		}
		return tx.CreateUser(alice)
	})
	if err != nil {
		t.Fatal(err)
	}
	dup := newUser("bob", RoleViewer)
	if err := d.Update(func(tx *Tx) error { return tx.CreateUser(dup) }); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("duplicate name: %v", err)
	}

	d.View(func(tx *Tx) error {
		users, err := tx.Users()
		if err != nil || len(users) != 2 || users[0].Username != "alice" || users[1].Username != "bob" {
			t.Errorf("Users = %+v, %v", users, err)
		}
		if u, err := tx.UserByName("bob"); err != nil || u.ID != bob.ID {
			t.Errorf("UserByName = %+v, %v", u, err)
		}
		if _, err := tx.UserByName("carol"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing user: %v", err)
		}
		if ok, _ := tx.HasEnabledAdmin(); !ok {
			t.Error("no enabled admin found")
		}
		return nil
	})

	alice.Disabled = true
	if err := d.Update(func(tx *Tx) error { return tx.UpdateUser(alice) }); err != nil {
		t.Fatal(err)
	}
	d.View(func(tx *Tx) error {
		if ok, _ := tx.HasEnabledAdmin(); ok {
			t.Error("a disabled admin counted")
		}
		return nil
	})
	alice.Username = "alicia"
	if err := d.Update(func(tx *Tx) error { return tx.UpdateUser(alice) }); err == nil {
		t.Error("renaming a user was accepted")
	}
}

func TestBindings(t *testing.T) {
	d, _ := openTemp(t)
	pub := Binding{ID: NewID(), Subject: Everyone, Folder: "public", Role: RoleContributor, Kind: KindPublic}
	if err := d.Update(func(tx *Tx) error { return tx.PutBinding(pub) }); err != nil {
		t.Fatal(err)
	}
	bad := pub
	bad.ID, bad.Role = NewID(), RoleAdmin
	if err := d.Update(func(tx *Tx) error { return tx.PutBinding(bad) }); err == nil {
		t.Error("an admin binding was accepted")
	}
	d.View(func(tx *Tx) error {
		bs, err := tx.Bindings()
		if err != nil || len(bs) != 1 || bs[0] != pub {
			t.Errorf("Bindings = %+v, %v", bs, err)
		}
		return nil
	})
}

func TestFailedUpdateChangesNothing(t *testing.T) {
	d, _ := openTemp(t)
	boom := errors.New("boom")
	err := d.Update(func(tx *Tx) error {
		if err := tx.CreateUser(newUser("alice", RoleAdmin)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	d.View(func(tx *Tx) error {
		if users, _ := tx.Users(); len(users) != 0 {
			t.Errorf("users after a failed update: %+v", users)
		}
		return nil
	})
}

func TestDumpHidesSecrets(t *testing.T) {
	d, _ := openTemp(t)
	u := newUser("alice", RoleAdmin)
	d.Update(func(tx *Tx) error {
		tx.tx.Bucket(bucketSessions).Put([]byte("sessiontokenhash"), []byte(`{"id":"s1"}`))
		tx.tx.Bucket(bucketSessionIDs).Put([]byte("s1"), []byte("sessiontokenhash"))
		tx.tx.Bucket(bucketLinks).Put([]byte("linktokenhash"), []byte(`{"id":"l1"}`))
		tx.tx.Bucket(bucketLinkIDs).Put([]byte("l1"), []byte("linktokenhash"))
		return tx.CreateUser(u)
	})
	var key []byte
	d.View(func(tx *Tx) error { key = tx.DeviceKey(); return nil })

	var buf bytes.Buffer
	if err := d.Dump(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, secret := range []string{"$argon2id", "sessiontokenhash", "linktokenhash", string(key)} {
		if strings.Contains(out, secret) {
			t.Errorf("dump contains %q:\n%s", secret, out)
		}
	}
	for _, want := range []string{"users (1)", `"username":"alice"`, u.ID, `{"id":"s1"}`, `{"id":"l1"}`, "schema\t1"} {
		if !strings.Contains(out, want) {
			t.Errorf("dump lacks %q:\n%s", want, out)
		}
	}
}

func TestDumpEscapesWhatATerminalWouldActOn(t *testing.T) {
	d, _ := openTemp(t)
	d.Update(func(tx *Tx) error {
		up := tx.tx.Bucket(bucketUploaders)
		up.Put([]byte("public/plain.txt"), []byte(`{"user":"u-1"}`))
		up.Put([]byte("public/\x1b]0;owned\x07.txt"), []byte(`{"user":"u-1"}`))
		up.Put([]byte("public/two words.txt"), []byte(`{"user":"u-1"}`))
		return tx.tx.Bucket(bucketBindings).Put([]byte("b1"), []byte("{\"folder\":\"x\u009b31m\u202egnp.exe\U000e0041\"}"))
	})
	var buf bytes.Buffer
	if err := d.Dump(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsAny(out, "\x1b\x07\u009b\u202e\U000e0041") {
		t.Errorf("control characters reached the output:\n%q", out)
	}
	for _, want := range []string{"  public/plain.txt\t", `  "public/\x1b]0;owned\a.txt"` + "\t", `  "public/two words.txt"` + "\t",
		`{"folder":"x\u009b31m\u202egnp.exe\udb40\udc41"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("dump lacks %q:\n%s", want, out)
		}
	}
}

func TestOpenRefusesAFileOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	d, path := openTemp(t)
	d.Close()
	os.Chmod(path, 0o644)
	if _, err := Open(path); !errors.Is(err, ErrOpenToOthers) {
		t.Errorf("mode 0644: %v", err)
	}
	os.Chmod(path, 0o600)
	again, err := Open(path)
	if err != nil {
		t.Fatalf("mode 0600: %v", err)
	}
	again.Close()
}
