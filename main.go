package main

import (
	"log"
	"net/http"

	refresh "github.com/RonyFrancis/jwt_go_example/handlers/refresh"
	sessions "github.com/RonyFrancis/jwt_go_example/handlers/sessions"
	welcome "github.com/RonyFrancis/jwt_go_example/handlers/welcome"
)

func main() {
	// "Signin" and "Welcome" are the handlers that we will implement
	http.HandleFunc("/signin", sessions.Signin)
	http.HandleFunc("/welcome", welcome.Welcome)
	http.HandleFunc("/refresh", refresh.Refresh)

	// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}
