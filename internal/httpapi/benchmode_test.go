//go:build !bench

package httpapi

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/nobletk/gocalbox/internal/benchmode"
)

type plainHandler struct{}

func (*plainHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// A normal build serves with its own windows and logs no request, whatever
// the benchmark settings say.
func TestANormalBuildIgnoresTheBenchmarkSettings(t *testing.T) {
	t.Setenv(benchmode.EnvConnWindow, "16M")
	t.Setenv(benchmode.EnvStreamWindow, "1M")
	t.Setenv(benchmode.EnvRequestLog, filepath.Join(t.TempDir(), "requests.jsonl"))
	if err := benchmode.Init(); err != nil {
		t.Fatal(err)
	}
	h := &plainHandler{}
	srv := NewServer(h)
	if srv.HTTP2.MaxReceiveBufferPerConnection != receiveWindowPerConnection || srv.HTTP2.MaxReceiveBufferPerStream != receiveWindowPerStream {
		t.Errorf("windows %d, %d", srv.HTTP2.MaxReceiveBufferPerConnection, srv.HTTP2.MaxReceiveBufferPerStream)
	}
	if got, ok := srv.Handler.(*plainHandler); !ok || got != h {
		t.Errorf("the handler was wrapped: %T", srv.Handler)
	}
}
