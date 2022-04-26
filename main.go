package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/mitchellh/mapstructure"
	"github.com/ory/oathkeeper/pipeline/authn"
	"github.com/ory/oathkeeper/x"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

var address string
var username string
var password string
var claims string

var rootCmd = &cobra.Command{
	Use: "oathkeeper-google",
	Run: func(cmd *cobra.Command, args []string) {
		tpl, err := x.NewTemplate("claims").Parse(claims)
		if err != nil {
			log.Fatal("failed to parse claims template: ", err)
		}
		e := echo.New()
		e.HideBanner = true
		e.HidePort = true
		e.Use(middleware.Logger())
		e.Use(middleware.Recover())
		e.Use(middleware.BasicAuth(BasicAuthValidator))
		e.POST("/hydrators/token", HydrateToken(tpl))
		if err := e.Start(address); err != nil {
			log.Fatalf("failed to start server: %s", err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVar(&address, "address", ":8080", "address to listen on")
	rootCmd.Flags().StringVar(&username, "username", "oathkeeper", "username for oathkeeper hydrator authentication")
	rootCmd.Flags().StringVar(&password, "password", "", "password for oathkeeper hydrator authentication")
	rootCmd.Flags().StringVar(&claims, "claims", "{}", "go template for claims to be added to the token")
	rootCmd.MarkFlagRequired("password")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func HydrateToken(claimtpl *template.Template) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		ctx := req.Context()
		var as authn.AuthenticationSession
		if err := json.NewDecoder(req.Body).Decode(&as); err != nil {
			return c.NoContent(http.StatusBadRequest)
		}
		var tpl bytes.Buffer
		if err := claimtpl.Execute(&tpl, as); err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		var rres map[string]interface{}
		if err := json.Unmarshal(tpl.Bytes(), &rres); err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		var res struct {
			Audience string                 `mapstructure:"aud"`
			Claims   map[string]interface{} `mapstructure:",remain"`
		}
		if err := mapstructure.Decode(rres, &res); err != nil {
			return c.NoContent(http.StatusBadRequest)
		}
		creds, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		ts, err := idtoken.NewTokenSource(ctx, res.Audience, option.WithCredentials(creds))
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		t, err := ts.Token()
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		as.SetHeader(
			"Authorization",
			strings.Join([]string{strings.Title(t.TokenType), t.AccessToken}, " "),
		)
		return c.JSON(http.StatusOK, as)
	}
}

func BasicAuthValidator(u, p string, c echo.Context) (bool, error) {
	userCmp := subtle.ConstantTimeCompare([]byte(u), []byte(username))
	passCmp := subtle.ConstantTimeCompare([]byte(p), []byte(password))
	return userCmp == 1 || passCmp == 1, nil
}
