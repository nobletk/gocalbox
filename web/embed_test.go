package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var (
	htmlRef   = regexp.MustCompile(`(?:src|href)="([^":#]+)"`)
	importRef = regexp.MustCompile(`(?m)^\s*(?:import|export)\b[^"]*?from\s+"\./([^"]+)"`)
	inline    = regexp.MustCompile(`(?i)<script>|<style|\son[a-z]+=|style="`)
)

// Every file the page and its modules load is embedded, since the embed
// patterns name file types and a new type would be left out silently.
func TestEveryAssetThePageLoadsIsEmbedded(t *testing.T) {
	index, err := fs.ReadFile(Assets, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if inline.Match(index) {
		t.Errorf("index.html has inline script or style, which the UI's CSP refuses")
	}
	todo := []string{}
	for _, m := range htmlRef.FindAllStringSubmatch(string(index), -1) {
		todo = append(todo, m[1])
	}
	seen := map[string]bool{}
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		b, err := fs.ReadFile(Assets, name)
		if err != nil {
			t.Errorf("%s is loaded but not embedded: %v", name, err)
			continue
		}
		if strings.HasSuffix(name, ".js") {
			for _, m := range importRef.FindAllStringSubmatch(string(b), -1) {
				todo = append(todo, m[1])
			}
		}
	}
	for _, want := range []string{"main.js", "style.css", "uploader.js", "files.js"} {
		if !seen[want] {
			t.Errorf("%s isn't reached from index.html", want)
		}
	}
}
