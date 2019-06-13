package welcome

import (
	"fmt"
	"net/http"

	calims "github.com/RonyFrancis/jwt_go_example/repository/claims"
	token "github.com/RonyFrancis/jwt_go_example/repository/tokenrepo"
)

var jwtKey = []byte("my_secret_key")

// Welcome handler
func Welcome(w http.ResponseWriter, r *http.Request) {
	to := &token.Token{}
	c := to.Fetchtoken(w, r)
	fmt.Println(c)
	// Initialize a new instance of `Claims`
	claims := calims.NewClaims()
	to.ValidateToken(c, claims, w)
	if to.Err != nil {
		return
	}
	// Finally, return the welcome message to the user, along with their
	// username given in the token
	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
