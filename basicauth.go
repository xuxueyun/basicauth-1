package basicauth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// Given a http.Request it will return the username/password from
// basic auth.
func GetUserPass(r *http.Request) (username, password string) {
	authHdr := r.Header.Get("Authorization")

	tokens := strings.Split(authHdr, " ")
	if len(tokens) != 2 {
		return
	}

	if tokens[0] != "Basic" {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		return
	}

	userPass := strings.SplitN(string(decoded), ":", 2)
	if len(userPass) == 2 {
		username = userPass[0]
		password = userPass[1]
		return
	} else if len(userPass) == 1 {
		username = userPass[0]
		return
	}

	return
}

// Add the basic auth version of the username, password to the http.Header
func AddBasicAuth(h http.Header, username, password string) {
	auth := []byte(username + ":" + password)
	authEnc := base64.StdEncoding.EncodeToString(auth)
	h.Set("Authorization", "Basic "+authEnc)
}
