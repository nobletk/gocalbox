package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

const hidden = "(hidden)"

// Dump writes every record for inspection, one per line under its bucket's
// name. Password hashes, the device key, and the token hashes that key
// sessions and links are left out.
func (d *DB) Dump(w io.Writer) error {
	return d.bolt.View(func(tx *bolt.Tx) error {
		for _, name := range buckets {
			b := tx.Bucket(name)
			if _, err := fmt.Fprintf(w, "%s (%d)\n", name, b.Stats().KeyN); err != nil {
				return err
			}
			err := b.ForEach(func(k, v []byte) error {
				key, value := string(k), string(v)
				switch {
				case bytes.Equal(name, bucketMeta) && bytes.Equal(k, keyDeviceKey):
					value = hidden
				case bytes.Equal(name, bucketUsers):
					value = withoutField(v, "hash")
				case bytes.Equal(name, bucketSessions), bytes.Equal(name, bucketLinks):
					key = hidden
				case bytes.Equal(name, bucketSessionIDs), bytes.Equal(name, bucketLinkIDs):
					value = hidden
				}
				_, err := fmt.Fprintf(w, "  %s\t%s\n", printable(key), escaped(value))
				return err
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// printable quotes a key that holds a character a terminal would act on, or
// one that reorders the text after it, such as an escape sequence or a bidi
// control in an uploaded file's name.
func printable(key string) string {
	if q := strconv.Quote(key); q != `"`+key+`"` || strings.ContainsAny(key, " \t") {
		return q
	}
	return key
}

// escaped writes the same characters of a value as \u escapes. JSON escapes
// only the C0 controls itself, and an escape keeps a JSON value valid.
func escaped(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`\ufffd`)
		case strconv.IsPrint(r):
			b.WriteRune(r)
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

func withoutField(v []byte, field string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		return "(unreadable record)"
	}
	delete(m, field)
	out, err := json.Marshal(m)
	if err != nil {
		return "(unreadable record)"
	}
	return string(out)
}
