package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

const testIssuer = "https://issuer.test"

type fixture struct {
	key     *rsa.PrivateKey
	handler *handler
	calls   []*http.Request
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: key}
	wt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls = append(f.calls, r)
	}))
	t.Cleanup(wt.Close)

	cfg := config{
		issuer:         testIssuer,
		audience:       "test-aud",
		allowedOwners:  []string{"Alice"},
		allowedRefs:    []string{"refs/heads/main"},
		registry:       "ghcr.io",
		watchtowerURL:  wt.URL,
		watchtowerAuth: "wt-secret",
	}
	keys := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	f.handler = &handler{
		cfg:      cfg,
		verifier: oidc.NewVerifier(testIssuer, keys, &oidc.Config{ClientID: cfg.audience}),
		client:   wt.Client(),
	}
	return f
}

func (f *fixture) token(t *testing.T, overrides map[string]any) string {
	t.Helper()
	c := map[string]any{
		"iss":              testIssuer,
		"aud":              "test-aud",
		"exp":              time.Now().Add(5 * time.Minute).Unix(),
		"iat":              time.Now().Unix(),
		"repository":       "alice/My-App",
		"repository_owner": "alice",
		"ref":              "refs/heads/main",
	}
	for k, v := range overrides {
		c[k] = v
	}
	payload, _ := json.Marshal(c)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fixture) post(t *testing.T, token, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hook"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestDefaultImageFromRepository(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, f.token(t, nil), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected 1 watchtower call, got %d", len(f.calls))
	}
	call := f.calls[0]
	if got := call.URL.Query().Get("image"); got != "ghcr.io/alice/my-app" {
		t.Errorf("image = %q", got)
	}
	if got := call.Header.Get("Authorization"); got != "Bearer wt-secret" {
		t.Errorf("watchtower auth = %q", got)
	}
}

func TestImageOverride(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, f.token(t, nil), "?image=ghcr.io/alice/other-name")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := f.calls[0].URL.Query().Get("image"); got != "ghcr.io/alice/other-name" {
		t.Errorf("image = %q", got)
	}
}

func TestRejected(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		query  string
		token  string // used verbatim if set
		status int
	}{
		{name: "no token", token: "-", status: http.StatusUnauthorized},
		{name: "garbage token", token: "not.a.jwt", status: http.StatusUnauthorized},
		{name: "wrong audience", claims: map[string]any{"aud": "other"}, status: http.StatusUnauthorized},
		{name: "wrong issuer", claims: map[string]any{"iss": "https://evil.test"}, status: http.StatusUnauthorized},
		{name: "expired", claims: map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}, status: http.StatusUnauthorized},
		{name: "other owner", claims: map[string]any{"repository": "mallory/app", "repository_owner": "mallory"}, status: http.StatusForbidden},
		{name: "other branch", claims: map[string]any{"ref": "refs/heads/feature"}, status: http.StatusForbidden},
		{name: "pull request ref", claims: map[string]any{"ref": "refs/pull/1/merge"}, status: http.StatusForbidden},
		{name: "repository owner mismatch", claims: map[string]any{"repository": "mallory/app"}, status: http.StatusForbidden},
		{name: "override other owner", query: "?image=ghcr.io/mallory/app", status: http.StatusForbidden},
		{name: "override other registry", query: "?image=docker.io/alice/app", status: http.StatusForbidden},
		{name: "override owner prefix only", query: "?image=ghcr.io/alicex/app", status: http.StatusForbidden},
		{name: "override with tag", query: "?image=ghcr.io/alice/app:main", status: http.StatusBadRequest},
		{name: "override with comma", query: "?image=ghcr.io/alice/app,ghcr.io/mallory/app", status: http.StatusBadRequest},
		{name: "override with traversal", query: "?image=ghcr.io/alice/../mallory/app", status: http.StatusBadRequest},
		{name: "override empty name", query: "?image=ghcr.io/alice/", status: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tok := tc.token
			switch tok {
			case "":
				tok = f.token(t, tc.claims)
			case "-":
				tok = ""
			}
			rec := f.post(t, tok, tc.query)
			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d (%s)", rec.Code, tc.status, strings.TrimSpace(rec.Body.String()))
			}
			if len(f.calls) != 0 {
				t.Errorf("watchtower was called")
			}
		})
	}
}

func TestWatchtowerFailure(t *testing.T) {
	f := newFixture(t)
	wt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer wt.Close()
	f.handler.cfg.watchtowerURL = wt.URL
	rec := f.post(t, f.token(t, nil), "")
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}
