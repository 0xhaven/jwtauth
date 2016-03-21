package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/jacobhaven/jwtauth/auth"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

var (
	port string
)

func init() {
	flag.StringVar(&port, "port", "8080", "port to listen on")
}

func main() {
	flag.Parse()
	db, err := gorm.Open("sqlite3", "test.db")
	if err != nil {
		log.Fatal("failed to connect database")
	}

	authServer := auth.NewServerCustom(db, 10*time.Second, 60*time.Second)
	http.HandleFunc("/login", authServer.LoginHandler)
	http.Handle("/", authServer.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Authenticated!")
	}), nil))

	fmt.Println("Listening at", net.JoinHostPort("", port))
	http.ListenAndServe(net.JoinHostPort("", port), nil)
}
