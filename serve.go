package oidc

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"sync"
)

type OIDCHandler struct {
	Config      Config
	upstream    *oidc.Provider
	once        sync.Once
	oauthConfig *oauth2.Config
	parser      *jwt.Parser
}

func New(cfg Config) (*OIDCHandler, error) {
	provider, err := oidc.NewProvider(context.Background(), cfg.Get("ISSUER"))
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
	return &OIDCHandler{
		Config:      cfg,
		upstream:    provider,
		oauthConfig: oauthConfig,
		parser:      nil,
	}, nil
}

func (o *OIDCHandler) home(w http.ResponseWriter, r *http.Request) {
	slog.Info("made it here")
	var msg string
	switch {
	case o.checkToken(r):
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

	// Parse the token
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		fmt.Printf("Error parsing token: %v\n", err)
		return
	}

	// Check if the token is valid and extract claims
	_, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(res, "Invalid claims", http.StatusBadRequest)
		return
	}

	// set the token as a cookie
	cookie := &http.Cookie{
		Name:  "token",
		Value: tokenString,
	}
	http.SetCookie(res, cookie)

	// Define the HTML template
	res.Write([]byte("success"))
}

func (o *OIDCHandler) logout(writer http.ResponseWriter, request *http.Request) {
	// TODO clear
	http.Redirect(writer, request, "/", http.StatusFound)
}

func (o *OIDCHandler) checkToken(req *http.Request) bool {
	// do i have a jwt cookie?
	tokenString, _ := req.Cookie("token")
	// TODO is it valid?
	if tokenString == nil {
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
