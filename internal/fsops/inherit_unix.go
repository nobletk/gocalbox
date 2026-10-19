//go:build unix

package fsops

import (
	"os"
	"slices"
)

// inherited is what a file created in a folder gets from the folder: its
// group, and where the kernel can tell, its permissions and access ACL. A
// staged file placed in the folder by a link or a rename keeps what it got
// in the staging folder, so it is given these first.
type inherited struct {
	// gid is -1 where the file keeps the group it was created with.
	gid int
	// full is set when mode and acl are known too; acl is nil for a file
	// without an access ACL.
	full bool
	mode os.FileMode
	acl  []byte
}

// mayChgrp reports whether the server may give one of its files the group
// gid.
var mayChgrp = func(gid int) bool {
	if os.Geteuid() == 0 || gid == os.Getegid() {
		return true
	}
	groups, err := os.Getgroups()
	return err == nil && slices.Contains(groups, gid)
}

// allowed reports whether the server may give in to the file f.
func (in inherited) allowed(f *os.File) bool {
	if in.gid < 0 {
		return true
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	gid, ok := groupOf(info)
	return ok && gid == in.gid || mayChgrp(in.gid)
}

// inherit gives the staged file what a file created in the folder dir would
// get from it.
func (s *Service) inherit(staged, dir string) error {
	in, err := inheritedFrom(s.root, dir)
	if err != nil {
		return err
	}
	f, err := s.root.Open(staged)
	if err != nil {
		return err
	}
	defer f.Close()
	return in.giveTo(f)
}

// reinherit is for Windows, where a placed file is given its folder's
// permissions after the placement.
func (s *Service) reinherit(string, string) error { return nil }
