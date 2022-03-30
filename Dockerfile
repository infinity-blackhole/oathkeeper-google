FROM golang:1.18.0-bullseye@sha256:996ee073842215953635bcc11b2cda8775b543dbe4a903a6792ad7dd4dcd0017 AS build

WORKDIR /usr/src/app

# Download dependencies
COPY go.mod go.sum ./
RUN --mount=id=go-mod-cache,type=cache,sharing=locked,target=/go/pkg/mod/cache \
  go mod download

# Build executable
COPY main.go ./
RUN --mount=id=go-mod-cache,type=cache,sharing=locked,target=/go/pkg/mod/cache \
  go build -o /go/bin/app

# Create minimal image
FROM gcr.io/distroless/base-debian11@sha256:ce8bc342dd7eeb0baccbef2ce00afc0c72af1ea166794f55ef8f434fd7c8b515
COPY --from=build /go/bin/app /app

EXPOSE 8080
CMD [ "/app" ]
