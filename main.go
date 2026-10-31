// deployhook accepts GitHub Actions OIDC tokens and asks Watchtower to update
// the container image belonging to the calling repository.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

type config struct {
	listen         string
	issuer         string
	audience       string
	allowedOwners  []string
	allowedRefs    []string
	registry       string
	watchtowerURL  string
	watchtowerAuth string
}

func loadConfig() (config, error) {
	c := config{
		listen:         env("DEPLOYHOOK_LISTEN", ":8080"),
		issuer:         env("DEPLOYHOOK_ISSUER", githubIssuer),
		audience:       os.Getenv("DEPLOYHOOK_AUDIENCE"),
		allowedOwners:  list(os.Getenv("DEPLOYHOOK_ALLOWED_OWNERS")),
		allowedRefs:    list(env("DEPLOYHOOK_ALLOWED_REFS", "refs/heads/main")),
		registry:       strings.TrimSuffix(env("DEPLOYHOOK_REGISTRY", "ghcr.io"), "/"),
		watchtowerURL:  strings.TrimSuffix(env("WATCHTOWER_URL", "http://watchtower:8080"), "/"),
		watchtowerAuth: os.Getenv("WATCHTOWER_TOKEN"),
	}
	var missing []string
	if c.audience == "" {
		missing = append(missing, "DEPLOYHOOK_AUDIENCE")
	}
	if len(c.allowedOwners) == 0 {
		missing = append(missing, "DEPLOYHOOK_ALLOWED_OWNERS")
	}
	if c.watchtowerAuth == "" {
		missing = append(missing, "WATCHTOWER_TOKEN")
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Keys are fetched lazily (and refreshed on unknown key IDs), so startup
	// doesn't depend on reaching GitHub.
	keys := oidc.NewRemoteKeySet(ctx, cfg.issuer+"/.well-known/jwks")
	h := &handler{
		cfg:      cfg,
		verifier: oidc.NewVerifier(cfg.issuer, keys, &oidc.Config{ClientID: cfg.audience}),
		client:   &http.Client{Timeout: 10 * time.Minute},
	}

	mux := http.NewServeMux()
	mux.Handle("POST /hook", h)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("listening", "addr", cfg.listen, "owners", cfg.allowedOwners, "refs", cfg.allowedRefs)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
