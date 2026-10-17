package events

import (
	"fmt"
	"log"
	"strings"
)

func LogHandler(ev Event) {
	var b strings.Builder
	fmt.Fprintf(&b, "Event [%s] outcome=%s actor=%s", ev.Type, ev.Outcome, ev.Actor.ID)
	if ev.Actor.Name != "" {
		fmt.Fprintf(&b, "(%s)", ev.Actor.Name)
	}
	if ev.Actor.Session != "" {
		fmt.Fprintf(&b, "[%s]", ev.Actor.Session)
	}
	if ev.Actor.RemoteAddr != "" {
		fmt.Fprintf(&b, "@%s", ev.Actor.RemoteAddr)
	}
	if ev.RequestID != "" {
		fmt.Fprintf(&b, " req=%s", ev.RequestID)
	}
	fmt.Fprintf(&b, " path=%q", ev.Path)
	if ev.Target != "" {
		fmt.Fprintf(&b, " target=%q", ev.Target)
	}
	if ev.Range != "" {
		fmt.Fprintf(&b, " range=%q", ev.Range)
	}
	if ev.Size > 0 {
		fmt.Fprintf(&b, " size=%d", ev.Size)
	}
	if u := ev.Upload; u != nil {
		fmt.Fprintf(&b, " upload=%s", u.ID)
		if u.Part > 0 {
			fmt.Fprintf(&b, " part=%d", u.Part)
		}
	}
	if ev.Detail != "" {
		fmt.Fprintf(&b, " detail=%q", ev.Detail)
	}
	log.Print(b.String())
}
