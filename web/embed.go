// Package web embeds the browser UI so the binary does not depend on the
// working directory. New asset types need a pattern in the directive below.
package web

import "embed"

//go:embed *.html *.js *.css
var Assets embed.FS
