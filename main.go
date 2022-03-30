package main

import (
	"context"
	"encoding/json"
	"flag"
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
	http.ListenAndServe(address, mux)
}

func HandleHydrateToken(w http.ResponseWriter, req *http.Request) {
	encoder := json.NewEncoder(w)
	decoder := json.NewDecoder(req.Body)
	w.WriteHeader(handleHydrateToken(encoder, decoder))
}

func handleHydrateToken(encoder *json.Encoder, decoder *json.Decoder) int {
	var as authn.AuthenticationSession
	if err := decoder.Decode(&as); err != nil {
		return http.StatusBadRequest
	}
	aud, ok := as.Extra["audience"].(string)
	if !ok {
		return http.StatusBadRequest
	}
	tk, err := getIdToken(aud)
	if err != nil {
		return http.StatusInternalServerError
	}
	as.SetHeader("Authorization", tk)
	if err := encoder.Encode(as); err != nil {
		return http.StatusInternalServerError
	}
	return http.StatusOK
}

func getIdToken(audience string) (string, error) {
	ts, err := idtoken.NewTokenSource(context.Background(), audience)
	if err != nil {
		return "", err
	}
	t, err := ts.Token()
	if err != nil {
		return "", err
	}
	return strings.Join([]string{t.TokenType, t.AccessToken}, " "), nil
}
