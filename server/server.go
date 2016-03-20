package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"

	"github.com/jacobhaven/jwtauth/server/auth"
)

var (
	port string
)

func init() {
	flag.StringVar(&port, "port", "8080", "port to listen on")
}

func main() {
	flag.Parse()
	http.HandleFunc("/login", auth.LoginHandler)
	http.Handle("/", auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Authenticated!")
	})))
	http.ListenAndServe(net.JoinHostPort("", port), nil)
}
