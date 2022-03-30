package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/spf13/cobra"
	"google.golang.org/api/idtoken"
)

var rootCmd = &cobra.Command{
	Use: "oathkeeper-google",
	Run: func(cmd *cobra.Command, args []string) {
		mux := http.NewServeMux()
		mux.HandleFunc("/hydrators/token", HandleHydrateToken)
		if err := http.ListenAndServe(address, mux); err != nil {
			log.Fatalf("failed to start server: %s", err)
		}
	},
}

var address string
var username string
var password string

func init() {
	rootCmd.Flags().StringVar(&address, "address", ":8080", "address to listen on")
	rootCmd.Flags().StringVar(&username, "username", "oathkeeper", "username for oathkeeper hydrator authentication")
	rootCmd.Flags().StringVar(&password, "password", "", "password for oathkeeper hydrator authentication")
	rootCmd.MarkFlagRequired("password")
}

func main() {
	log.Fatal(rootCmd.Execute())
}

func HandleHydrateToken(w http.ResponseWriter, req *http.Request) {
	basicAuthUser, basicAuthPwd, ok := req.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Missing Basic Auth", http.StatusUnauthorized)
		return
	}
	userCmp := subtle.ConstantTimeCompare([]byte(basicAuthUser), []byte(username))
	passCmp := subtle.ConstantTimeCompare([]byte(basicAuthPwd), []byte(password))
	if userCmp != 1 || passCmp != 1 {
		http.Error(w, "Credentials mismatch", http.StatusUnauthorized)
		return
	}
	var as authn.AuthenticationSession
	if err := json.NewDecoder(req.Body).Decode(&as); err != nil {
		http.Error(w, "Masformed body", http.StatusBadRequest)
		return
	}
	aud := req.URL.Query().Get("audience")
	if aud == "" {
		http.Error(w, "Missing audience", http.StatusBadRequest)
		return
	}
	ts, err := idtoken.NewTokenSource(req.Context(), aud)
	if err != nil {
		http.Error(w, "Token source error", http.StatusInternalServerError)
		return
	}
	t, err := ts.Token()
	if err != nil {
		http.Error(w, "Token fetch error", http.StatusInternalServerError)
		return
	}
	as.SetHeader(
		"Authorization",
		strings.Join([]string{t.TokenType, t.AccessToken}, " "),
	)
	if err := json.NewEncoder(w).Encode(as); err != nil {
		http.Error(w, "Encoding error", http.StatusInternalServerError)
		return
	}
}
