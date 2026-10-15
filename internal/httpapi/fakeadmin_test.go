package httpapi

import (
	"context"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/state"
)

// The admin and link calls of fakeAccounts answer f.err when it is set, and
// otherwise a fixed result.

func (f *fakeAccounts) InspectInvite(string, auth.Client) (auth.InviteInfo, error) {
	return auth.InviteInfo{Role: state.RoleViewer}, f.err
}

func (f *fakeAccounts) AcceptInvite(_ context.Context, _, username, _ string, c auth.Client) (auth.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients = append(f.clients, c)
	if f.err != nil {
		return auth.Grant{}, f.err
	}
	return f.grant(username), nil
}

func (f *fakeAccounts) InspectReset(string, auth.Client) (auth.ResetInfo, error) {
	return auth.ResetInfo{Username: "tester"}, f.err
}

func (f *fakeAccounts) AcceptReset(_ context.Context, _, _ string, c auth.Client) (auth.Grant, []auth.RevokedLink, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients = append(f.clients, c)
	if f.err != nil {
		return auth.Grant{}, nil, f.err
	}
	return f.grant("tester"), []auth.RevokedLink{}, nil
}

func (f *fakeAccounts) Users(auth.Identity) ([]auth.UserInfo, error) {
	return []auth.UserInfo{{ID: tester.User.ID, Username: "tester", Role: state.RoleAdmin}}, f.err
}

func (f *fakeAccounts) CreateInvite(_ context.Context, _ auth.Identity, req auth.InviteRequest) (auth.NewLink, error) {
	return auth.NewLink{ID: "0123456789abcdef", Kind: state.KindInvite, Token: "TOKEN", Role: req.Role, Expires: time.Now().Add(time.Hour)}, f.err
}

func (f *fakeAccounts) UpdateUser(_ context.Context, _ auth.Identity, userID string, _ auth.UserUpdate) (auth.UserInfo, error) {
	return auth.UserInfo{ID: userID}, f.err
}

func (f *fakeAccounts) CreateResetLink(context.Context, auth.Identity, string) (auth.NewLink, error) {
	return auth.NewLink{ID: "fedcba9876543210", Kind: state.KindReset, Token: "TOKEN", Expires: time.Now().Add(time.Hour)}, f.err
}

func (f *fakeAccounts) Links(auth.Identity) ([]auth.LinkInfo, error) { return []auth.LinkInfo{}, f.err }

func (f *fakeAccounts) RevokeLink(context.Context, auth.Identity, string) error { return f.err }

func (f *fakeAccounts) DeleteUser(context.Context, auth.Identity, string) (string, error) {
	return "", f.err
}

func (f *fakeAccounts) Bindings(auth.Identity) ([]auth.BindingInfo, error) {
	return []auth.BindingInfo{}, f.err
}

func (f *fakeAccounts) CreateBinding(_ context.Context, _ auth.Identity, subject, folder string, role state.Role) (auth.BindingInfo, error) {
	return auth.BindingInfo{ID: "b", Subject: subject, Folder: folder, Role: role, Kind: state.KindCustom}, f.err
}

func (f *fakeAccounts) DeleteBinding(context.Context, auth.Identity, string) error { return f.err }

func (f *fakeAccounts) AllSessions(auth.Identity, string) ([]auth.AdminSessionInfo, error) {
	return []auth.AdminSessionInfo{}, f.err
}

func (f *fakeAccounts) EndSession(context.Context, auth.Identity, string) error { return f.err }
