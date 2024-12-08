package oidc_backend

import (
	"net/http"
	"testing"
	"time"
)

func TestServe(t *testing.T) {
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		if f, err := req.Cookie("foo"); err == nil {
			println("found cookie: ", f.String())
		}
		c := &http.Cookie{
			Name:    "foo",
			Value:   "bar",
			Expires: time.Now().Add(time.Hour),
			/*Secure:      true,
			HttpOnly:    true,
			SameSite:    http.SameSiteLaxMode,*/
		}
		http.SetCookie(res, c)
		res.Write([]byte("<h1>hello</h1>"))
	})

	http.ListenAndServe("localhost:8080", nil)
}
