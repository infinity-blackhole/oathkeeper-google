package oathkeepergoogle

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/ory/oathkeeper/pipeline/authn"
	"google.golang.org/api/idtoken"
)

func init() {
	username := os.Getenv("OATHKEEPER_GOOGLE_HYDRATOR_AUTH_BASIC_USERNAME")
	password := os.Getenv("OATHKEEPER_GOOGLE_HYDRATOR_AUTH_BASIC_PASSWORD")
	hydratorHandler := HandleHydrateToken()
	authHandler := HandleBasicAuth(username, password, hydratorHandler)
	functions.HTTP("HydrateToken", authHandler.ServeHTTP)
}

func HandleHydrateToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var as authn.AuthenticationSession
		if err := json.NewDecoder(r.Body).Decode(&as); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		aud := r.URL.Query().Get("audience")
		if aud == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ts, err := idtoken.NewTokenSource(r.Context(), aud)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		t, err := ts.Token()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		as.SetHeader(
			"Authorization",
			strings.Join([]string{t.TokenType, t.AccessToken}, " "),
		)
		if err := json.NewEncoder(w).Encode(as); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
}

func HandleBasicAuth(username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qs := r.URL.Query()
		u := qs.Get("username")
		p := qs.Get("password")
		ucmp := subtle.ConstantTimeCompare([]byte(u), []byte(username))
		pcmp := subtle.ConstantTimeCompare([]byte(p), []byte(password))
		if ucmp != 1 || pcmp != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
