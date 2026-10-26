package httpapi

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/nobletk/gocalbox/internal/fsops"
)

// handleZip streams a folder as a zip archive, stored without compression.
// Every file goes through Open, which checks and records it as a download of
// its own, and every folder through List, which leaves out what the user may
// not see. Entries that vanish meanwhile are left out; any other error, once
// the archive has begun, can only cut the connection, so the client never
// takes a partial archive for a whole one. Linked folders are left out: a
// link may lead back to a folder above it.
func (a *api) handleZip(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	dir := r.URL.Query().Get("path")
	entries, err := a.files.List(r.Context(), dir)
	if err != nil {
		writeError(w, r, err)
		return
	}

	name := zipName(dir)
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": name + ".zip"})
	if disposition == "" {
		disposition = "attachment"
	}
	h.Set("Content-Disposition", disposition)
	h.Set("Content-Security-Policy", fileCSP)

	type folder struct {
		path, prefix string
		entries      []fsops.Entry
	}
	zw := zip.NewWriter(w)
	stack := []folder{{dir, name + "/", entries}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: f.prefix, Method: zip.Store}); err != nil {
			panic(http.ErrAbortHandler)
		}
		var sub []folder
		for _, e := range f.entries {
			child := path.Join(f.path, e.Name)
			// Some extractors read a backslash as a separator, which would let a
			// name lead outside the folder they extract into.
			entry := strings.ReplaceAll(e.Name, `\`, "_")
			if !e.IsDir {
				if err := a.zipFile(zw, r, child, f.prefix+entry); err != nil {
					panic(http.ErrAbortHandler)
				}
				continue
			}
			if e.Link {
				continue
			}
			list, err := a.files.List(r.Context(), child)
			if gone(err) {
				continue
			}
			if err != nil {
				panic(http.ErrAbortHandler)
			}
			sub = append(sub, folder{child, f.prefix + entry + "/", list})
		}
		for i := len(sub) - 1; i >= 0; i-- {
			stack = append(stack, sub[i])
		}
	}
	if err := zw.Close(); err != nil {
		panic(http.ErrAbortHandler)
	}
}

// gone reports whether an entry vanished, or was replaced by something
// else, since its folder was listed.
func gone(err error) bool {
	return errors.Is(err, fsops.ErrNotFound) || errors.Is(err, fsops.ErrNotDir)
}

// zipFile adds one file; a file that is gone is left out.
func (a *api) zipFile(zw *zip.Writer, r *http.Request, p, name string) error {
	f, err := a.files.Open(r.Context(), p)
	if gone(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info := f.Info()
	hw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Modified: info.ModTime()})
	if err != nil {
		f.Finish(fsops.Transfer{Err: fmt.Errorf("%w: %v", fsops.ErrAborted, err)})
		return err
	}
	cw := &sentCounter{w: hw}
	// The size read at opening bounds what is sent, so a file that grows
	// meanwhile can't make its entry disagree with the size it was opened at.
	_, err = io.CopyN(cw, f.Content(), info.Size())
	t := fsops.Transfer{Sent: cw.n}
	switch {
	case cw.err != nil:
		t.Err = fmt.Errorf("%w: %v", fsops.ErrAborted, cw.err)
	case err != nil:
		t.Err = fmt.Errorf("read: %w", err)
	}
	f.Finish(t)
	return err
}

func zipName(dir string) string {
	base := path.Base(path.Clean("/" + dir))
	if base == "/" {
		return "gocalbox"
	}
	return base
}

type sentCounter struct {
	w   io.Writer
	n   int64
	err error
}

func (c *sentCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if err != nil && c.err == nil {
		c.err = err
	}
	return n, err
}
