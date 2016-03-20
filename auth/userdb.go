package auth

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

// User is a gorm Model of a user table row, with
// username and bcrypt hashed password.
type User struct {
	Name           string `gorm:"primary_key"`
	HashedPassword []byte
}

func (as *Server) verifyLogin(username, password string) bool {
	user := &User{Name: username}
	as.db.FirstOrCreate(user)
	if len(user.HashedPassword) != 0 {
		return nil == bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password))
	}

	var err error
	user.HashedPassword, err = bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		log.Println(err)
		as.db.Delete(&user)
		return false
	}

	as.db.Save(&user)
	return true
}
