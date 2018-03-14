package activedirectory

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Need to test the shit out of this thing and capture fixtures.

var completeConfig = &Configuration{
	Url:           "TODO",
	Certificate:   "TODO",
	InsecureTLS:   false,
	StartTLS:      true,
	TLSMinVersion: "1.1",
	TLSMaxVersion: "1.2",
}

func TestMain(m *testing.M) {
	server := setup()
	code := m.Run()
	teardown(server)
	os.Exit(code)
}

// Based on
// https://golang.org/pkg/net/http/httptest/#example_NewTLSServer
func setup() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
}

func teardown(server *httptest.Server) {
	server.Close()
}

func TestSearch(t *testing.T) {

	client := NewClient(completeConfig)

	baseDN := map[Field][]string{
		DomainComponent: {"example", "com"},
	}

	filters := map[Field][]string{
		CommonName: {"Becca Petrin"},
	}

	entries, err := client.Search(baseDN, filters)
	if err != nil {
		t.Error(err.Error())
		t.FailNow()
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry but received %d: %s", len(entries), entries)
		t.FailNow()
	}
	// TODO check the entry
}

func TestUpdatePassword(t *testing.T) {
	// TODO
}

func TestUpdateUsername(t *testing.T) {
	// TODO
}

func TestMultipleUrls(t *testing.T) {
	// TODO
}

func TestNoUrls(t *testing.T) {
	// TODO
}

func TestNoCertificate(t *testing.T) {
	// TODO
}

func TestInsecureTLS(t *testing.T) {
	// TODO
}

func TestDontStartTLS(t *testing.T) {
	// TODO
}

func TestNoTLSMinVersion(t *testing.T) {
	// TODO - also need to test that its not 1.0, which is BAD
}

func TestNoTLSMaxVersion(t *testing.T) {
	// TODO
}
