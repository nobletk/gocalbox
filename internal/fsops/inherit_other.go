//go:build !unix && !windows

package fsops

import "os"

type inherited struct{}

func inheritedFrom(*os.Root, string) (inherited, error) { return inherited{}, nil }

func (inherited) allowed(*os.File) bool { return true }

func (s *Service) inherit(string, string) error { return nil }

func (s *Service) reinherit(string, string) error { return nil }
