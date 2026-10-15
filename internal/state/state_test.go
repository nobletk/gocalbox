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

func TestSessions(t *testing.T) {
	d, _ := openTemp(t)
	now := time.Now().UTC()
	a := Session{ID: "aaaa", User: "u-1", Created: now, LastSeen: now, AuthTime: now, Epoch: 2, UserAgent: "ua", IP: "192.0.2.1"}
	b := Session{ID: "bbbb", User: "u-2", Created: now}
	err := d.Update(func(tx *Tx) error {
		if err := tx.PutSession([]byte("key-a"), a); err != nil {
			return err
		}
		return tx.PutSession([]byte("key-b"), b)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Update(func(tx *Tx) error { return tx.PutSession(nil, a) }); err == nil {
		t.Error("a session without a key was stored")
	}
	all := map[string]Session{}
	d.View(func(tx *Tx) error {
		return tx.Sessions(func(k []byte, s Session) error { all[string(k)] = s; return nil })
	})
	if len(all) != 2 || !all["key-a"].Created.Equal(a.Created) || all["key-a"].IP != a.IP || all["key-b"].User != "u-2" {
		t.Errorf("sessions = %+v", all)
	}

	renewed := a
	if err := d.Update(func(tx *Tx) error {
		if err := tx.DeleteSession([]byte("key-a")); err != nil {
			return err
		}
		return tx.PutSession([]byte("key-a2"), renewed)
	}); err != nil {
		t.Fatal(err)
	}
	d.Update(func(tx *Tx) error { return tx.DeleteSession([]byte("missing")) })
	d.View(func(tx *Tx) error {
		if got := string(tx.tx.Bucket(bucketSessionIDs).Get([]byte("aaaa"))); got != "key-a2" {
			t.Errorf("index after renewal = %q", got)
		}
		if tx.tx.Bucket(bucketSessions).Get([]byte("key-a")) != nil {
			t.Error("the old key survived")
		}
		return nil
	})
	d.Update(func(tx *Tx) error { return tx.DeleteSession([]byte("key-b")) })
	d.View(func(tx *Tx) error {
		if tx.tx.Bucket(bucketSessionIDs).Get([]byte("bbbb")) != nil || tx.tx.Bucket(bucketSessions).Get([]byte("key-b")) != nil {
			t.Error("a deleted session left a record or an index entry")
		}
		return nil
	})
}

func TestLinks(t *testing.T) {
	d, _ := openTemp(t)
	now := time.Now().UTC().Round(0)
	inv := Link{ID: "a1", Kind: KindInvite, Role: RoleViewer, Username: "carol", Note: "phone", CreatedBy: "u-1", Created: now, Expires: now.Add(time.Hour)}
	reset := Link{ID: "b2", Kind: KindReset, User: "u-2", CreatedBy: "console", Created: now, Expires: now.Add(time.Hour)}
	err := d.Update(func(tx *Tx) error {
		for _, bad := range []Link{
			{Kind: KindInvite, Role: RoleViewer},
			{ID: "c3", Kind: "other"},
			{ID: "c3", Kind: KindInvite},
		} {
			if err := tx.PutLink([]byte("k"), bad); err == nil {
				t.Errorf("stored %+v", bad)
			}
		}
		if err := tx.PutLink(nil, inv); err == nil {
			t.Error("stored a link without a key")
		}
		if err := tx.PutLink([]byte("key-inv"), inv); err != nil {
			return err
		}
		return tx.PutLink([]byte("key-reset"), reset)
	})
	if err != nil {
		t.Fatal(err)
	}
	d.View(func(tx *Tx) error {
		if l, err := tx.Link([]byte("key-inv")); err != nil || l != inv {
			t.Errorf("Link = %+v, %v", l, err)
		}
		if key, l, err := tx.LinkByID("b2"); err != nil || string(key) != "key-reset" || l != reset {
			t.Errorf("LinkByID = %q, %+v, %v", key, l, err)
		}
		if _, err := tx.Link([]byte("missing")); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing key: %v", err)
		}
		if _, _, err := tx.LinkByID("missing"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing ID: %v", err)
		}
		return nil
	})

	if !inv.Unused(now) || inv.Unused(inv.Expires) {
		t.Error("Unused misjudges the expiry")
	}
	used := inv
	used.Used = now
	if used.Unused(now) {
		t.Error("a used link is unused")
	}

	err = d.Update(func(tx *Tx) error {
		if err := tx.DeleteLink([]byte("key-inv")); err != nil {
			return err
		}
		if err := tx.DeleteLink([]byte("key-inv")); err != nil {
			return err
		}
		return tx.tx.Bucket(bucketLinks).Put([]byte("broken"), []byte("{"))
	})
	if err != nil {
		t.Fatal(err)
	}
	d.View(func(tx *Tx) error {
		if tx.tx.Bucket(bucketLinkIDs).Get([]byte("a1")) != nil {
			t.Error("the ID index outlived the link")
		}
		var seen []string
		tx.Links(func(k []byte, l Link) error { seen = append(seen, string(k)+"="+l.ID); return nil })
		if strings.Join(seen, ",") != "broken=,key-reset=b2" {
			t.Errorf("Links passed %q", seen)
		}
		return nil
	})
	if err := d.Update(func(tx *Tx) error { return tx.DeleteLink([]byte("broken")) }); err != nil {
		t.Errorf("deleting an unreadable record: %v", err)
	}
}

func TestDeleteUserFreesTheName(t *testing.T) {
	d, _ := openTemp(t)
	bob := newUser("bob", RoleViewer)
	b := Binding{ID: NewID(), Subject: bob.ID, Folder: "shared", Role: RoleViewer, Kind: KindCustom}
	err := d.Update(func(tx *Tx) error {
		if err := tx.CreateUser(bob); err != nil {
			return err
		}
		return tx.PutBinding(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = d.Update(func(tx *Tx) error {
		if got, err := tx.Binding(b.ID); err != nil || got != b {
			t.Errorf("Binding = %+v, %v", got, err)
		}
		if err := tx.DeleteBinding(b.ID); err != nil {
			return err
		}
		if err := tx.DeleteBinding(b.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting a binding twice: %v", err)
		}
		if _, err := tx.Binding(b.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted binding: %v", err)
		}
		if err := tx.DeleteUser(bob.ID); err != nil {
			return err
		}
		if err := tx.DeleteUser(bob.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("deleting a user twice: %v", err)
		}
		if _, err := tx.UserByName("bob"); !errors.Is(err, ErrNotFound) {
			t.Errorf("the name still names the user: %v", err)
		}
		return tx.CreateUser(newUser("bob", RoleContributor))
	})
	if err != nil {
		t.Errorf("a new bob: %v", err)
	}
}

func TestSessionByID(t *testing.T) {
	d, _ := openTemp(t)
	now := time.Now().UTC()
	s := Session{ID: "s1", User: "u-1", Created: now, LastSeen: now, AuthTime: now, Epoch: 3}
	err := d.Update(func(tx *Tx) error {
		if err := tx.PutSession([]byte("old"), s); err != nil {
			return err
		}
		if err := tx.DeleteSession([]byte("old")); err != nil {
			return err
		}
		return tx.PutSession([]byte("new"), s)
	})
	if err != nil {
		t.Fatal(err)
	}
	d.View(func(tx *Tx) error {
		if got, err := tx.SessionByID("s1"); err != nil || got.ID != "s1" || got.Epoch != 3 {
			t.Errorf("SessionByID = %+v, %v", got, err)
		}
		if _, err := tx.SessionByID("s2"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a missing session: %v", err)
		}
		return nil
	})
	d.Update(func(tx *Tx) error { return tx.DeleteSession([]byte("new")) })
	d.View(func(tx *Tx) error {
		if _, err := tx.SessionByID("s1"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a deleted session: %v", err)
		}
		return nil
	})
}
