package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/nobletk/gocalbox/internal/audit"
	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

const commandsUsage = `  gocalbox users add -username NAME -role admin|contributor|viewer [-state PATH] [-audit-log PATH]
  gocalbox users list [-state PATH]
  gocalbox users passwd [-state PATH] [-audit-log PATH] NAME
  gocalbox state dump [-state PATH]

The users and state commands work only while the server is stopped. users add
and users passwd read the password from standard input, or ask for it twice
on a terminal.
`

var errUsage = errors.New("usage")

func command(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var err error
	switch args[0] {
	case "users":
		err = runUsers(args[1:], stdin, stdout, stderr)
	case "state":
		err = runState(args[1:], stdout, stderr)
	}
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	}
	fmt.Fprintf(stderr, "gocalbox: %v\n", err)
	return 1
}

func runUsers(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "Usage:\n%s", commandsUsage)
		return errUsage
	}
	switch args[0] {
	case "add":
		return usersAdd(args[1:], stdin, stdout, stderr)
	case "list":
		return usersList(args[1:], stdout, stderr)
	case "passwd":
		return usersPasswd(args[1:], stdin, stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command \"users %s\"\nUsage:\n%s", args[0], commandsUsage)
	return errUsage
}

func runState(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "dump" {
		fmt.Fprintf(stderr, "Usage:\n%s", commandsUsage)
		return errUsage
	}
	flags := newFlagSet("state dump", stderr)
	statePath := flags.String("state", defaultStatePath(), "State file")
	if err := parse(flags, args[1:]); err != nil {
		return err
	}
	db, err := openExistingState(*statePath)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Dump(stdout)
}

func usersAdd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := newFlagSet("users add", stderr)
	username := flags.String("username", "", "Username: 3 to 32 characters from a-z, 0-9, '.', '_' and '-'")
	role := flags.String("role", "", "admin, contributor or viewer")
	statePath, auditPath, minLen := accountFlags(flags)
	if err := parse(flags, args); err != nil {
		return err
	}
	if *username == "" || *role == "" {
		fmt.Fprintln(stderr, "users add needs -username and -role")
		return errUsage
	}
	name, err := auth.NormalizeUsername(*username)
	if err != nil {
		return explain(err)
	}
	if !state.Role(*role).Valid() {
		return fmt.Errorf("invalid role %q: use admin, contributor or viewer", *role)
	}
	if err := checkMinLength(*minLen); err != nil {
		return err
	}
	c, err := openConsole(*statePath, *auditPath, *minLen, false, func(tx *state.Tx) error {
		if _, err := tx.UserByName(name); err == nil {
			return explain(auth.ErrUsernameTaken)
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer c.close()

	password, err := readNewPassword(stdin, stderr)
	if err != nil {
		return err
	}
	u, err := c.acc.CreateUser(consoleContext(), name, state.Role(*role), password)
	if err != nil {
		return explain(err)
	}
	if err := c.rec.Err(); err != nil {
		return fmt.Errorf("the user %s was created, but the audit record could not be written: %w", u.Username, err)
	}
	fmt.Fprintf(stdout, "Created %s (%s, %s).", u.Username, u.Role, u.ID)
	if u.Role.HasHome() {
		fmt.Fprintf(stdout, " The server creates the home folder /%s when it next starts.", auth.HomeOf(u.Username))
	}
	fmt.Fprintln(stdout)
	return nil
}

func usersPasswd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := newFlagSet("users passwd", stderr)
	statePath, auditPath, minLen := accountFlags(flags)
	if err := parse(flags, args); err != nil {
		return err
	}
	// Flags may also follow the username.
	rest := flags.Args()
	if len(rest) > 0 {
		if err := parse(flags, rest[1:]); err != nil {
			return err
		}
	}
	if len(rest) == 0 || flags.NArg() > 0 {
		fmt.Fprintln(stderr, "users passwd needs exactly one username")
		return errUsage
	}
	noUser := fmt.Errorf("no user named %q", rest[0])
	name, err := auth.NormalizeUsername(rest[0])
	switch {
	case errors.Is(err, auth.ErrUsernameTaken):
		return noUser
	case err != nil:
		return explain(err)
	}
	if err := checkMinLength(*minLen); err != nil {
		return err
	}
	c, err := openConsole(*statePath, *auditPath, *minLen, true, func(tx *state.Tx) error {
		if _, err := tx.UserByName(name); err != nil {
			return noUser
		}
		return nil
	})
	if err != nil {
		return err
	}
	defer c.close()

	password, err := readNewPassword(stdin, stderr)
	if err != nil {
		return err
	}
	u, err := c.acc.SetPassword(consoleContext(), name, password)
	if err != nil {
		return explain(err)
	}
	if err := c.rec.Err(); err != nil {
		return fmt.Errorf("the password of %s was changed, but the audit record could not be written: %w", u.Username, err)
	}
	fmt.Fprintf(stdout, "Changed the password of %s; every session of the account has ended.\n", u.Username)
	return nil
}

func usersList(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("users list", stderr)
	statePath := flags.String("state", defaultStatePath(), "State file")
	if err := parse(flags, args); err != nil {
		return err
	}
	db, err := openExistingState(*statePath)
	if err != nil {
		return err
	}
	defer db.Close()
	var users []state.User
	if err := db.View(func(tx *state.Tx) error { var err error; users, err = tx.Users(); return err }); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tROLE\tSTATUS\tCREATED\tID")
	for _, u := range users {
		status := "enabled"
		switch {
		case u.Disabled:
			status = "disabled"
		case u.PasswordDisabled:
			status = "password disabled"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Username, u.Role, status, u.CreatedAt.Format(time.DateOnly), u.ID)
	}
	return tw.Flush()
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}

func parse(flags *flag.FlagSet, args []string) error {
	err := flags.Parse(args)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		return errUsage
	}
	return err
}

func accountFlags(flags *flag.FlagSet) (statePath, auditPath *string, minLen *int) {
	statePath = flags.String("state", defaultStatePath(), "State file")
	auditPath = flags.String("audit-log", defaultAuditPath(), "Audit log the change is recorded in")
	minLen = flags.Int("min-password-length", auth.DefaultMinPasswordLength,
		"Fewest characters a password may have; give the same value as the server's -min-password-length")
	return statePath, auditPath, minLen
}

func checkMinLength(n int) error {
	if n < auth.LowestMinPasswordLength || n > auth.MaxPasswordBytes {
		return fmt.Errorf("-min-password-length must be between %d and %d, got %d", auth.LowestMinPasswordLength, auth.MaxPasswordBytes, n)
	}
	return nil
}

const inUse = "the server is running, or another users command; stop it or use the admin page"

func openExistingState(path string) (*state.DB, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no state file at %s; give its path with -state", path)
	}
	return openState(path)
}

func openState(path string) (*state.DB, error) {
	db, err := state.Open(path)
	if errors.Is(err, state.ErrLocked) {
		return nil, fmt.Errorf("%s is in use: %s", path, inUse)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return db, nil
}

// auditRecorder writes the console's events straight to the audit log. The
// log's lock keeps a running server from appending at the same time.
type auditRecorder struct {
	w *audit.Writer
}

func (r auditRecorder) Publish(ev events.Event) {
	ev.Time = time.Now().UTC()
	r.w.Handle(ev)
}

func (r auditRecorder) Err() error   { return r.w.Err() }
func (r auditRecorder) Close() error { return r.w.Close() }

type console struct {
	db  *state.DB
	rec auditRecorder
	acc *auth.Accounts
}

// openConsole runs check on the state file before it creates the audit log,
// so a command refused by it leaves no new file behind.
func openConsole(statePath, auditPath string, minLen int, stateMustExist bool, check func(*state.Tx) error) (*console, error) {
	c := &console{}
	openDB := func() error {
		var err error
		if stateMustExist {
			c.db, err = openExistingState(statePath)
		} else if err = os.MkdirAll(filepath.Dir(statePath), 0o700); err == nil {
			c.db, err = openState(statePath)
		}
		if err != nil {
			return err
		}
		return c.db.View(check)
	}
	openLog := func() error {
		if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
			return err
		}
		w, err := audit.Open(auditPath)
		if errors.Is(err, audit.ErrLocked) {
			return fmt.Errorf("%s is in use: %s", auditPath, inUse)
		}
		c.rec.w = w
		return err
	}
	// The file that exists is locked first: when a running server holds it,
	// the command stops before creating the other one.
	steps := []func() error{openDB, openLog}
	if !stateMustExist && !exists(statePath) && exists(auditPath) {
		steps = []func() error{openLog, openDB}
	}
	for _, step := range steps {
		if err := step(); err != nil {
			c.close()
			return nil, err
		}
	}
	c.acc = auth.New(auth.Config{
		DB:     c.db,
		Hasher: auth.NewHasher(auth.DefaultParams, 1, time.Minute),
		Policy: auth.Policy{MinLength: minLen},
		Events: c.rec,
	})
	return c, nil
}

func (c *console) close() {
	if c.rec.w != nil {
		c.rec.Close()
	}
	if c.db != nil {
		c.db.Close()
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func consoleContext() context.Context {
	return events.WithActor(context.Background(), events.Actor{ID: events.ConsoleID})
}

func explain(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidUsername):
		return errors.New("invalid username: use 3 to 32 characters from a-z, 0-9, '.', '_' and '-', starting and ending with a letter or digit")
	case errors.Is(err, auth.ErrUsernameTaken):
		return errors.New("this username is taken or reserved")
	}
	return err
}

// readNewPassword reads one line, or on a terminal asks twice without
// echoing.
func readNewPassword(in io.Reader, prompt io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(prompt, "New password: ")
		first, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(prompt)
		if err != nil {
			return "", err
		}
		fmt.Fprint(prompt, "Repeat it: ")
		second, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(prompt)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New("the two passwords differ")
		}
		return string(first), nil
	}
	// A longer line is cut, and the policy then refuses it as too long.
	line, err := bufio.NewReader(io.LimitReader(in, auth.MaxPasswordBytes+3)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line == "" {
		return "", errors.New("no password on standard input")
	}
	return line, nil
}
