FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./...
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /deployhook .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /deployhook /deployhook
EXPOSE 8080
ENTRYPOINT ["/deployhook"]
