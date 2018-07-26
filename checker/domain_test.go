package checker

import (
	"net"
	"strings"
	"testing"

	"github.com/mhale/smtpd"
)

func noopHandler(_ net.Addr, _ string, _ []string, _ []byte) {}

func TestNoTLS(t *testing.T) {
	srv := &smtpd.Server{Handler: noopHandler, Appname: "", Hostname: ""}

	// Use net.Listen to get a random available port assignment
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		if err := srv.Serve(ln); err != nil {
			if strings.Contains(err.Error(), "closed") {
				return
			}
			t.Fatal(err)
		}
	}()

	result := CheckHostname("", ln.Addr().String(), nil)
	t.Error(result)
}
