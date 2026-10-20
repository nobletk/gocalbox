//go:build !bench

package httpapi

import "net/http"

func logRequests(h http.Handler) http.Handler { return h }
