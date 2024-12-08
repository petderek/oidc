package oidc_backend

import (
	"net/http"
	"testing"
)

func TestServe(t *testing.T) {
	oidc, err := New(&EnvConfig{PanicOnEmpty: true})
	if err != nil {
		t.Fatalf("could not initialize oidc: %s", err)
	}

	err = http.ListenAndServeTLS("localhost:443", "crt.pem", "key.pem", oidc)
	if err != nil {
		t.Fatalf("failed server: %s", err)
	}
}
