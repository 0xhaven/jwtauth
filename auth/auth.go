package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
)

// Server provides an authentication layer, with auth tokens provided
// by a LoginHandler and sensitive
type Server struct {
	KeyStore
	db *gorm.DB
}

const (
	// DefaultKeyStep instructs to generate a new key every hour.
	DefaultKeyStep = time.Hour
	// DefaultKeyLifetime instructs to have keys expire after one week.
	DefaultKeyLifetime = 7 * 24 * time.Hour
)

// NewServer creates an Server back by a SQL db with the default
// key step and lifetime.
func NewServer(db *gorm.DB) *Server {
	return NewServerCustom(db, DefaultKeyStep, DefaultKeyLifetime)
}

// NewServerCustom creates an Server with custom key step and lifetime.
func NewServerCustom(db *gorm.DB, keyStep, keyLifetime time.Duration) *Server {
	db.CreateTable(&User{})
	return &Server{
		KeyStore: NewKeystore(db, keyStep, keyLifetime),
		db:       db,
	}
}

// getKey returns the key in the KeyStore associated with a token's kid.
func (as *Server) getKey(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Claims["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid kid: %v", token.Claims["kid"])
	}

	k, ok := as.Get(kid)
	if !ok {
		return nil, fmt.Errorf("couldn't find kid %s", kid)
	}

	return k.Key, nil
}

// A UserFilter determines whether or not a given username is authorized.
type UserFilter func(string) bool

// defaultFilter used if a nil filter is given. Checks that username isn't "".
func defultFilter(username string) bool {
	return username != ""
}

// Wrap places an authentication layer in front of the given Handler.
// If filter isn't nil, it accepts only usernames that pass that test.
func (as *Server) Wrap(h http.Handler, filter UserFilter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		token, err := jwt.Parse(cookie.Value, as.getKey)
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

		if filter == nil {
			filter = defultFilter
		}
		if username, ok := token.Claims["username"].(string); !ok || !filter(username) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		h.ServeHTTP(w, r)
	})
}

// LoginHandler provides a simple login/signup endpoint that issues a new JWT as
// a cookie.
func (as *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username, password := r.Form.Get("username"), r.Form.Get("password")
	if !as.verifyLogin(username, password) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	token, expiry, err := as.NewToken(map[string]interface{}{
		"username": username,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{Name: "jwt", Value: token, Expires: expiry})
}
