package oidc_backend

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"net/http"
)

type OIDCHandler struct {
	Upstream    *oidc.Provider
	OauthConfig *oauth2.Config
	Parser      *jwt.Parser
}

func (o *OIDCHandler) home(w http.ResponseWriter, r *http.Request) {
	html := `
        <html>
        <body>
            <h1>basic app</h1>
        </body>
        </html>`
	fmt.Fprint(w, html)
}

func (o *OIDCHandler) login(res http.ResponseWriter, request *http.Request) {
	state := "TODOSTATE"
	url := o.OauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(res, request, url, http.StatusFound)
}

func (o *OIDCHandler) callback(res http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	code := req.URL.Query().Get("code")

	// Exchange the authorization code for a token
	rawToken, err := o.OauthConfig.Exchange(ctx, code)
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

	// Define the HTML template
	res.Write([]byte("success"))
}

func (o *OIDCHandler) logout(writer http.ResponseWriter, request *http.Request) {
	// TODO clear
	http.Redirect(writer, request, "/", http.StatusFound)
}

func (o *OIDCHandler) HandleHTTP(res http.ResponseWriter, req *http.Request) {
	var msg string
	switch {
	case o.checkToken(req):
		msg = "token is valid"
	case o.refreshToken(res, req):
		msg = "token was refreshed"
	default:
		msg = "no token"
	}
	res.Write([]byte(msg))
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
