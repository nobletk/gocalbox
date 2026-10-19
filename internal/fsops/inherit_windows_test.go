package fsops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// dacl is the permissions of path, in SDDL.
func dacl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// grantGuests gives the folder dir an entry for the built-in Guests group
// that its new files and folders inherit.
func grantGuests(t *testing.T, dir string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(guests),
		},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Skipf("can't change the folder's permissions: %v", err)
	}
}

// A placed file gets the permissions its folder passes on, as a file
// written there does, not those of the staging folder; both upload paths
// and the resumable upload's placement agree.
func TestAPlacedFileGetsItsFoldersPermissions(t *testing.T) {
	a := newAccessEnv(t)
	dir := filepath.Join(a.root, "public", "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	grantGuests(t, dir)
	a.upload(alice, "public/shared", "staged.bin", "x")
	if _, _, err := a.svc.Adopt(as(alice), a.stage("x"), "public/shared", "adopted.bin", func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	directUploads(a.svc)
	a.upload(alice, "public/shared", "direct.bin", "x")
	want := dacl(t, filepath.Join(dir, "direct.bin"))
	if !strings.Contains(want, ";BG)") {
		t.Fatalf("a file written in the folder didn't inherit its entry: %s", want)
	}
	for _, name := range []string{"staged.bin", "adopted.bin"} {
		if got := dacl(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s: %s, a file written there %s", name, got, want)
		}
	}
}

// A folder that passes no permissions on to files leaves the placed file
// with those it got in the staging folder: an empty list would let no one
// read it.
func TestAFolderThatPassesNothingOnLeavesTheFileReadable(t *testing.T) {
	a := newAccessEnv(t)
	dir := filepath.Join(a.root, "public", "closed")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinAdministratorsSid, windows.WinLocalSystemSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, folderOnly(sid))
	}
	entries = append(entries, folderOnly(user.User.Sid))
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Skipf("can't change the folder's permissions: %v", err)
	}
	a.upload(alice, "public/closed", "a.bin", "readable")
	if got := a.read("public/closed/a.bin"); got != "readable" {
		t.Errorf("the placed file: %q", got)
	}
	if got := dacl(t, filepath.Join(dir, "a.bin")); !strings.Contains(got, "(A;") {
		t.Errorf("the placed file's permissions: %s", got)
	}
}

// folderOnly grants sid full access to a folder and the folders in it,
// passing nothing on to files.
func folderOnly(sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_ONLY_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
