package tokenrepo

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/RonyFrancis/jwt_go_example/repository/claims"
	"github.com/dgrijalva/jwt-go"
)

// Token for handling token related logic
type Token struct {
	Err error
}

var jwtKey = []byte("my_secret_key")

// Claims create claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Fetchtoken gets token from cookie
func (to *Token) Fetchtoken(w http.ResponseWriter, r *http.Request) *http.Cookie {
	// We can obtain the session token from the requests cookies, which come with every request
	c, err := r.Cookie("token")
	if err != nil {
		updateHeader(err, w)
		to.Err = err
		return nil
	}
	return c
}

// ValidateToken valid the token
func (to *Token) ValidateToken(c *http.Cookie, claims *claims.Claims, w http.ResponseWriter) {
	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	if to.Err != nil {
		fmt.Println("inside validate")
		return
	}
	tkn, err := jwt.ParseWithClaims(c.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		to.Err = errors.New("token not valid")
	}
	if err != nil {
		updateHeader(err, w)
		to.Err = err
	}
}

func updateHeader(err error, w http.ResponseWriter) {
	if err == http.ErrNoCookie || err == jwt.ErrSignatureInvalid {
		// If the cookie is not set, return an unauthorized status
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
	}
}

// GenerateNewToken hahhaha
func (to *Token) GenerateNewToken(time time.Time, claims *claims.Claims, w http.ResponseWriter) (string, error) {
	claims.ExpiresAt = time.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return "", err
	}
	return tokenString, nil
}

func (to *Token) IsTokenExpiring(claims *claims.Claims, w http.ResponseWriter) error {
	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return errors.New("token still valid")
	}
	return nil
}
