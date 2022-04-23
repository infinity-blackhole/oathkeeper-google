package main

import (
	"context"
	"log"

	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/ory/viper"

	"github.com/infinity-blackhole/oathkeeper-google/pkg/idtokenhydrator"
)

func init() {
	viper.AutomaticEnv()
	viper.SetDefault("port", "8080")
}

func main() {
	ctx := context.Background()
	port := viper.GetString("port")
	if port == "" {
		log.Fatalf("Missing port")
	}
	username := viper.GetString("hydrator_auth_basic_username")
	if username == "" {
		log.Fatalf("Missing hydrator_auth_basic_username")
	}
	password := viper.GetString("hydrator_auth_basic_password")
	if password == "" {
		log.Fatalf("Missing hydrator_auth_basic_password")
	}
	tkh := idtokenhydrator.BasicAuth(username, password, idtokenhydrator.TokenHydrator())
	if err := funcframework.RegisterHTTPFunctionContext(ctx, "/hydrators/idtoken", tkh.ServeHTTP); err != nil {
		log.Fatalf("funcframework.RegisterHTTPFunctionContext: %v\n", err)
	}
	if err := funcframework.Start(port); err != nil {
		log.Fatal(err)
	}
}
