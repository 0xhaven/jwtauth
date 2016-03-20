package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var defaultKeyStore = NewKeyStore(time.Hour, 168*time.Hour)

func getKey(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Claims["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid kid: %v", token.Claims["kid"])
	}
	k, ok := defaultKeyStore.Get(kid)
	if !ok {
		return nil, fmt.Errorf("couldn't find kid %s", kid)
	}

	return k.key, nil
}

func Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		token, err := jwt.Parse(cookie.Value, getKey)
		if err != nil || !token.Valid {
			if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorExpired != 0 {
					http.Error(w, "Token expired", http.StatusForbidden)
					return
				}
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func verifyLogin(username, password string) bool {
	// TODO properly salt, hash, store to DB
	return true
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username, password := r.Form.Get("username"), r.Form.Get("password")
	if !verifyLogin(username, password) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	token, k, err := defaultKeyStore.NewToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	token.Claims["username"] = username
	jwt, err := token.SignedString(k.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "jwt", Value: jwt, Expires: k.expiry})
}
