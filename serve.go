package oidc

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type OIDCHandler struct {
	Config      Config
	keyfunc     keyfunc.Keyfunc
	upstream    *oidc.Provider
	domain      string
	oauthConfig *oauth2.Config
	parser      *jwt.Parser
}

func New(cfg Config) (*OIDCHandler, error) {
	issuer := cfg.Get("ISSUER")
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, err
	}
	oauthConfig := &oauth2.Config{
		ClientID:     cfg.Get("CLIENT_ID"),
		ClientSecret: cfg.Get("CLIENT_SECRET"),
		RedirectURL:  cfg.Get("REDIRECT_URL"),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "openid", "phone"},
	}
	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{issuer + "/.well-known/jwks.json"})
	if err != nil {
		return nil, err
	}
	return &OIDCHandler{
		Config:      cfg,
		upstream:    provider,
		oauthConfig: oauthConfig,
		domain:      cfg.Get("DOMAIN"),
		parser:      &jwt.Parser{},
		keyfunc:     kf,
	}, nil
}

func (o *OIDCHandler) home(w http.ResponseWriter, r *http.Request) {
	slog.Info("made it here")
	var msg string
	var token string
	if cookie, _ := r.Cookie("token"); cookie != nil {
		token = cookie.Value
	}
	switch {
	case o.checkToken(token):
		msg = "you are logged in"
	case o.refreshToken(w, r):
		msg = "you are refreshed"
	default:
		msg = "you are not logged in"
	}
	html := fmt.Sprintf(`
        <html>
        <body>
            <h1>basic app</h1>
            <h2>%s</h2>
        </body>
        </html>`, msg)
	fmt.Fprint(w, html)
}

func (o *OIDCHandler) login(res http.ResponseWriter, request *http.Request) {
	state, _ := uuid.NewV7()
	url := o.oauthConfig.AuthCodeURL(state.String(), oauth2.AccessTypeOffline)
	slog.Info("redirect to: " + url)
	http.Redirect(res, request, url, http.StatusFound)
}

func (o *OIDCHandler) callback(res http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	code := req.URL.Query().Get("code")

	// Exchange the authorization code for a token
	rawToken, err := o.oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(res, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tokenString := rawToken.AccessToken

	// todo store some datas in the backend
	slog.Info("id " + rawToken.Extra("id_token").(string))

	// Parse the token
	if !o.checkToken(tokenString) {
		fmt.Printf("Error parsing token: %v\n", err)
		return
	}

	// set the token as a cookie
	http.SetCookie(res, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		SameSite: http.SameSiteLaxMode,
		Domain:   o.Config.Get("DOMAIN"),
		Secure:   true,
		HttpOnly: true,
	})
	http.Redirect(res, req, "/", http.StatusFound)
}

func (o *OIDCHandler) logout(res http.ResponseWriter, req *http.Request) {
	// clear cookie and force expire
	http.SetCookie(res, &http.Cookie{Name: "token", Value: "", Expires: time.Now().Add(-time.Hour)})
	http.Redirect(res, req, "/", http.StatusFound)
}

func (o *OIDCHandler) checkToken(token string) bool {
	// do i have a jwt cookie?
	if token == "" {
		return false
	}
	_, err := o.parser.Parse(token, o.keyfunc.KeyfuncCtx(context.TODO()))
	if err != nil {
		slog.Error("jwt failed: " + err.Error())
		return false
	}
	return true
}

func (o *OIDCHandler) refreshToken(res http.ResponseWriter, req *http.Request) bool {
	// TODO
	return false
}

var mux = http.NewServeMux()
var once sync.Once

func (o *OIDCHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	slog.Info("it worked")
	once.Do(func() {
		mux.HandleFunc("/", o.home)
		mux.HandleFunc("/login", o.login)
		mux.HandleFunc("/logout", o.logout)
		mux.HandleFunc("/callback", o.callback)
	})
	mux.ServeHTTP(res, req)
}
