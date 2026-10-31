# deployhook

A tiny receiver that lets GitHub Actions trigger an immediate
[Watchtower](https://containrrr.dev/watchtower/) update, with no secrets in the
calling repositories.

A workflow presents its [GitHub OIDC token](https://docs.github.com/en/actions/concepts/security/openid-connect).
deployhook verifies it, checks the repository owner and ref against its
configuration, and calls Watchtower's HTTP API to update just that repository's
image.

Watchtower only updates containers that are already running the named image, so
a valid request can't start anything new or change any configuration. The worst
it can do is redeploy an image you published yourself.

## Configuration

| Variable | Default | |
|---|---|---|
| `DEPLOYHOOK_AUDIENCE` | *required* | OIDC audience callers must request. Any unique string. |
| `DEPLOYHOOK_ALLOWED_OWNERS` | *required* | Comma-separated GitHub users/orgs whose repositories may trigger updates. |
| `WATCHTOWER_TOKEN` | *required* | Watchtower's `WATCHTOWER_HTTP_API_TOKEN`. |
| `WATCHTOWER_URL` | `http://watchtower:8080` | |
| `DEPLOYHOOK_ALLOWED_REFS` | `refs/heads/main` | Comma-separated refs allowed to deploy. |
| `DEPLOYHOOK_REGISTRY` | `ghcr.io` | Registry that images live under. |
| `DEPLOYHOOK_LISTEN` | `:8080` | |
| `DEPLOYHOOK_ISSUER` | `https://token.actions.githubusercontent.com` | |

Watchtower needs `WATCHTOWER_HTTP_API_UPDATE=true` and
`WATCHTOWER_HTTP_API_TOKEN`. To keep its scheduled runs as well, it also needs
`WATCHTOWER_HTTP_API_PERIODIC_POLLS=true`.

## API

`POST /hook` with `Authorization: Bearer <github-oidc-token>`.

The image defaults to `<registry>/<owner>/<repo>`, lowercased, which matches
`docker/metadata-action` with `images: ghcr.io/${{ github.repository }}`. To
update a differently named image under the same owner, pass `?image=<name>`
without a tag.

The request blocks until Watchtower finishes the update. Watchtower reports
success even when an update fails, so check Watchtower's own logs and
notifications for the outcome.

## Calling it from a workflow

Add this step after the image push:

```yaml
jobs:
  build:
    permissions:
      id-token: write   # required to get an OIDC token
      packages: write
      contents: read
    steps:
      # ... build and push ...
      - uses: <owner>/deployhook@main
        if: github.ref == 'refs/heads/main'
        with:
          url: https://deploy.example.com/hook
          audience: <DEPLOYHOOK_AUDIENCE>
          # image: ghcr.io/<owner>/<other-name>   # optional
```

Neither the URL nor the audience is a secret, so they can go straight in the
workflow or in repository/user variables.
