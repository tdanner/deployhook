package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// claims is the subset of the GitHub Actions OIDC token we use.
// https://docs.github.com/en/actions/reference/security/oidc#oidc-token-claims
type claims struct {
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
	Ref             string `json:"ref"`
	SHA             string `json:"sha"`
	Workflow        string `json:"workflow"`
	RunID           string `json:"run_id"`
}

type handler struct {
	cfg      config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// pathComponent matches one lowercase repository path component as defined by
// the OCI distribution spec. Commas in particular are excluded, since
// Watchtower would treat them as a list separator.
var pathComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)

var errForbidden = errors.New("forbidden")

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	tok, err := h.verifier.Verify(r.Context(), raw)
	if err != nil {
		slog.Warn("rejected token", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	var c claims
	if err := tok.Claims(&c); err != nil {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}

	log := slog.With("repo", c.Repository, "ref", c.Ref, "sha", c.SHA, "workflow", c.Workflow, "run", c.RunID)

	image, err := h.authorize(c, r.URL.Query().Get("image"))
	if err != nil {
		log.Warn("rejected request", "err", err)
		status := http.StatusBadRequest
		if errors.Is(err, errForbidden) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
		return
	}

	log = log.With("image", image)
	log.Info("triggering update")
	if err := h.triggerUpdate(r.Context(), image); err != nil {
		log.Error("update failed", "err", err)
		http.Error(w, "update failed", http.StatusBadGateway)
		return
	}
	log.Info("update finished")
	fmt.Fprintf(w, "updated %s\n", image)
}

// authorize checks the token's claims against the configured policy and
// returns the image (without tag) to update. If override is empty the image
// is derived from the repository name.
func (h *handler) authorize(c claims, override string) (string, error) {
	if !slices.ContainsFunc(h.cfg.allowedOwners, func(o string) bool { return strings.EqualFold(o, c.RepositoryOwner) }) {
		return "", fmt.Errorf("%w: owner %q not allowed", errForbidden, c.RepositoryOwner)
	}
	if !slices.Contains(h.cfg.allowedRefs, c.Ref) {
		return "", fmt.Errorf("%w: ref %q not allowed", errForbidden, c.Ref)
	}

	ownerPrefix := h.cfg.registry + "/" + strings.ToLower(c.RepositoryOwner) + "/"
	image := strings.ToLower(override)
	if image == "" {
		repoOwner, repoName, ok := strings.Cut(c.Repository, "/")
		if !ok || !strings.EqualFold(repoOwner, c.RepositoryOwner) {
			return "", fmt.Errorf("%w: malformed repository claim %q", errForbidden, c.Repository)
		}
		image = ownerPrefix + strings.ToLower(repoName)
	}

	rest, ok := strings.CutPrefix(image, ownerPrefix)
	if !ok {
		return "", fmt.Errorf("%w: image must be under %s", errForbidden, ownerPrefix)
	}
	for _, part := range strings.Split(rest, "/") {
		if !pathComponent.MatchString(part) {
			return "", fmt.Errorf("invalid image name %q (give the name without a tag or digest)", image)
		}
	}
	return image, nil
}

// triggerUpdate asks Watchtower to check for and apply a new version of image.
// Watchtower's API blocks until the update run completes.
func (h *handler) triggerUpdate(ctx context.Context, image string) error {
	// Don't let a CI client that gives up mid-update abort the update.
	ctx = context.WithoutCancel(ctx)
	u := h.cfg.watchtowerURL + "/v1/update?" + url.Values{"image": {image}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.cfg.watchtowerAuth)
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watchtower returned %s", resp.Status)
	}
	return nil
}
