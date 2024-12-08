package oidc_backend

import (
	"context"
	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"testing"
)

func TestServe(t *testing.T) {
	provider, err := oidc.NewProvider(context.Background(), "")
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}
	oauth2Config := &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "https://localhost/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "openid", "phone"},
	}
	oidc := &OIDCHandler{
		Upstream:    provider,
		OauthConfig: oauth2Config,
		Parser:      nil,
	}

	err = http.ListenAndServeTLS("localhost:443", "key.pem", "crt.pem", oidc)
	if err != nil {
		t.Fatalf("failed server: %s", err)
	}
}
