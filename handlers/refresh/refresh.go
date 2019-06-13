package Refresh

import (
	"fmt"
	"net/http"
	"time"

	calims "github.com/RonyFrancis/jwt_go_example/repository/claims"
	token "github.com/RonyFrancis/jwt_go_example/repository/tokenrepo"
)

var jwtKey = []byte("my_secret_key")

// Refresh does something
func Refresh(w http.ResponseWriter, r *http.Request) {
	// (BEGIN) The code uptil this point is the same as the first part of the `Welcome` route
	to := &token.Token{}
	c := to.Fetchtoken(w, r)
	fmt.Println(c)
	// Initialize a new instance of `Claims`
	claims := calims.NewClaims()
	to.ValidateToken(c, claims, w)
	if to.Err != nil {
		return
	}
	// (END) The code uptil this point is the same as the first part of the `Welcome` route

	err := to.IsTokenExpiring(claims, w)
	fmt.Println(err)
	if err != nil {
		return
	}
	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	tokenString, err := to.GenerateNewToken(expirationTime, claims, w)
	fmt.Println(err)
	if err != nil {
		return
	}
	// Set the new token as the users `session_token` cookie
	http.SetCookie(w, NewCookie(tokenString, expirationTime))
}

// NewCookie creates new cookie
func NewCookie(token string, time time.Time) *http.Cookie {
	return &http.Cookie{
		Name:    "session_token",
		Value:   token,
		Expires: time,
	}
}
