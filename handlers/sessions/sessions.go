package sessions

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("my_secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Credentials Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// Claims create claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Response struct for json response
type Response struct {
	Token          string    `json:"token"`
	ExpirationTime time.Time `json:"expiration_time"`
}

// Signin api
func Signin(w http.ResponseWriter, r *http.Request) {
	creds, vaildateRequestStatus := vaildateRequest(w, r)
	if vaildateRequestStatus != 0 {
		w.WriteHeader(vaildateRequestStatus)
		return
	}
	validatonStatus := vaildateUser(creds)
	if validatonStatus != 0 {
		w.WriteHeader(validatonStatus)
		return
	}
	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)
	tokenString, serverErrorStatus := createJwtToken(creds, expirationTime)
	if serverErrorStatus != 0 {
		w.WriteHeader(serverErrorStatus)
		return
	}
	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, NewCookie(tokenString, expirationTime))
	json.NewEncoder(w).Encode(Response{
		Token: tokenString, ExpirationTime: expirationTime,
	})
}

func vaildateRequest(w http.ResponseWriter, r *http.Request) (*Credentials, int) {
	var creds Credentials
	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		// If the structure of the body is wrong, return an HTTP error
		return nil, http.StatusBadRequest
	}
	return &creds, 0
}

func vaildateUser(creds *Credentials) int {
	// Get the expected password from our in memory map
	expectedPassword, ok := users[creds.Username]
	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || expectedPassword != creds.Password {
		return http.StatusUnauthorized
	}
	return 0
}

func createJwtToken(creds *Credentials, time time.Time) (string, int) {
	claims := NewClaims(creds, time)
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		return "", http.StatusInternalServerError
	}
	return tokenString, 0
}

// NewClaims create new claims
func NewClaims(creds *Credentials, time time.Time) *Claims {
	// Create the JWT claims, which includes the username and expiry time
	return &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: time.Unix(),
		},
	}
}

// NewCookie creates new cookie
func NewCookie(token string, time time.Time) *http.Cookie {
	return &http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: time,
	}
}
