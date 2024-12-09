package oidc

import (
	"fmt"
	"net/http"
	"testing"
)

func TestServe(t *testing.T) {
	oidc, err := New(&EnvConfig{PanicOnEmpty: true})
	if err != nil {
		t.Fatalf("could not initialize oidc: %s", err)
	}

	err = http.ListenAndServeTLS("secure.djp.fyi:8080", "crt.pem", "key.pem", oidc)
	if err != nil {
		t.Fatalf("failed server: %s", err)
	}
}

func TestAlsoHere(t *testing.T) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
	http.ListenAndServeTLS("home.djp.fyi:443", "crt.pem", "key.pem", nil)
}
