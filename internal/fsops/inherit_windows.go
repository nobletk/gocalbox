package fsops

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type inherited struct{}

func inheritedFrom(*os.Root, string) (inherited, error) { return inherited{}, nil }

func (inherited) allowed(*os.File) bool { return true }

// inherit is for Unix, where a staged file is given its folder's group and
// permissions before it is placed.
func (s *Service) inherit(string, string) error { return nil }

// reinherit gives the placed file the permissions its folder dir passes on
// to new files, in place of those it got in the staging folder, as
// `icacls /reset` does. A folder that passes none on leaves the file as it
// is: an empty list would let no one read it. A volume that keeps no
// permissions, such as FAT, is left alone.
func (s *Service) reinherit(dir, placed string) error {
	d, err := s.root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Before GetSecurityInfo, which doesn't expect an object without
	// permissions, as on FAT.
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(windows.Handle(d.Fd()), nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return err
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return nil
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(d.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil
	}
	passes := false
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0 {
			passes = true
			break
		}
	}
	if !passes {
		return nil
	}
	f, err := s.root.Open(placed)
	if err != nil {
		return err
	}
	defer f.Close()
	// Permissions are inherited only when set by name. The final path names
	// the file opened in the root, whatever junctions lie on the way, and
	// in long form, however long it is.
	name, err := finalPath(f)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, emptyACL(), nil)
}

// volumeNameGUID asks GetFinalPathNameByHandle for a path that names the
// volume by its GUID.
const volumeNameGUID = 0x1

// finalPath returns the path of the open file f, in the long form that
// starts with \\?\: with a drive letter, or, on a volume without one,
// with the volume's GUID.
func finalPath(f *os.File) (string, error) {
	path, err := finalPathAs(f, 0)
	if err != nil {
		return finalPathAs(f, volumeNameGUID)
	}
	return path, nil
}

func finalPathAs(f *os.File, flags uint32) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n)
	}
}

// emptyACL returns an ACL of no entries: a header of revision 2 and 8 bytes.
func emptyACL() *windows.ACL {
	buf := new([2]uint32)
	buf[0] = 2 | 8<<16
	return (*windows.ACL)(unsafe.Pointer(buf))
}
