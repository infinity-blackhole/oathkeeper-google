package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/spf13/cobra"
	"google.golang.org/api/idtoken"
)

var address string
var username string
var password string

var rootCmd = &cobra.Command{
	Use: "oathkeeper-google",
	Run: func(cmd *cobra.Command, args []string) {
		e := echo.New()
		e.Use(middleware.Logger())
		e.Use(middleware.Recover())
		e.Use(middleware.BasicAuth(HandleBasicAuth))
		e.POST("/hydrators/token", HandleHydrateToken)
		if err := e.Start(address); err != nil {
			log.Fatalf("failed to start server: %s", err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVar(&address, "address", ":8080", "address to listen on")
	rootCmd.Flags().StringVar(&username, "username", "oathkeeper", "username for oathkeeper hydrator authentication")
	rootCmd.Flags().StringVar(&password, "password", "", "password for oathkeeper hydrator authentication")
	rootCmd.MarkFlagRequired("password")
}

func main() {
	log.Fatal(rootCmd.Execute())
}

func HandleHydrateToken(c echo.Context) error {
	req := c.Request()
	var as authn.AuthenticationSession
	if err := json.NewDecoder(req.Body).Decode(&as); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	aud := req.URL.Query().Get("audience")
	if aud == "" {
		return c.NoContent(http.StatusBadRequest)
	}
	ts, err := idtoken.NewTokenSource(req.Context(), aud)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	t, err := ts.Token()
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	as.SetHeader(
		"Authorization",
		strings.Join([]string{t.TokenType, t.AccessToken}, " "),
	)
	return c.JSON(http.StatusOK, as)
}

func HandleBasicAuth(u, p string, c echo.Context) (bool, error) {
	userCmp := subtle.ConstantTimeCompare([]byte(u), []byte(username))
	passCmp := subtle.ConstantTimeCompare([]byte(p), []byte(password))
	return userCmp == 1 || passCmp == 1, nil
}
