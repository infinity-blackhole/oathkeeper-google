package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/ory/oathkeeper/pipeline/authn"
	"google.golang.org/api/idtoken"
)

var address string

func init() {
	flag.StringVar(&address, "address", ":8080", "address to listen on")
}

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/hydrators/token", HandleHydrateToken)
	if err := http.ListenAndServe(address, mux); err != nil {
		log.Fatalf("failed to start server: %s", err)
	}
}

func HandleHydrateToken(w http.ResponseWriter, req *http.Request) {
	var as authn.AuthenticationSession
	if err := json.NewDecoder(req.Body).Decode(&as); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aud := req.URL.Query().Get("audience")
	if aud == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ts, err := idtoken.NewTokenSource(req.Context(), aud)
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
		return
	}
}
