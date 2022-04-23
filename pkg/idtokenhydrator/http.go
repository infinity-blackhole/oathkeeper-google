package idtokenhydrator

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ory/oathkeeper/pipeline/authn"
	"google.golang.org/api/idtoken"
)

func TokenHydrator() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var as authn.AuthenticationSession
		if err := json.NewDecoder(r.Body).Decode(&as); err != nil {
			http.Error(w, "Fail to decode body", http.StatusBadRequest)
			return
		}
		aud := r.URL.Query().Get("audience")
		if aud == "" {
			http.Error(w, "Missing Audience", http.StatusBadRequest)
			return
		}
		ts, err := idtoken.NewTokenSource(r.Context(), aud)
		if err != nil {
			http.Error(w, "Fail to connect token source", http.StatusInternalServerError)
			return
		}
		t, err := ts.Token()
		if err != nil {
			http.Error(w, "Fail to generate new token", http.StatusInternalServerError)
			return
		}
		as.SetHeader(
			"Authorization",
			strings.Join([]string{t.TokenType, t.AccessToken}, " "),
		)
		if err := json.NewEncoder(w).Encode(as); err != nil {
			http.Error(w, "Fail to encode response", http.StatusInternalServerError)
		}
	})
}

func BasicAuth(username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Missing Authorization", http.StatusUnauthorized)
			return
		}
		ucmp := subtle.ConstantTimeCompare([]byte(u), []byte(username))
		pcmp := subtle.ConstantTimeCompare([]byte(p), []byte(password))
		if ucmp != 1 || pcmp != 1 {
			http.Error(w, "Bad credentials", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
