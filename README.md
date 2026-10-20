# traefik-plugin-s3-bucket

A Traefik middleware plugin that lets clients such as Yocto/BitBake read
objects from an S3-compatible bucket (AWS S3, Cloudflare R2, RustFS, MinIO)
over HTTPS with **one shared token**, instead of an AWS signature on every
request.

The plugin checks the token, turns the request into a plain object `GET` or
`HEAD` for the configured bucket, signs it with AWS Signature Version 4 and
passes it on to the Traefik service that points at the bucket endpoint.
`Range` and conditional headers (`If-None-Match`, `If-Modified-Since`) are
passed through.

It is deliberately small: no cache, no token API, no UI. For those see
[bucket-cache](https://github.com/thomaskhub/bucket-cache).

## What clients can do

- `GET` and `HEAD` of single objects only. Other methods get `405`, query
  strings are dropped, and listing the bucket is not possible.
- The token can be sent three ways:
  - in the path: `https://cache.example.com/sstate/t/<token>/<key>` (easiest
    for BitBake mirrors),
  - as `Authorization: Bearer <token>`,
  - as the password of HTTP Basic auth (any user name), e.g. from `~/.netrc`.
- A missing or wrong token gets `401`. The client's own `Authorization`,
  `Cookie` and `X-Amz-*` headers never reach the bucket.

## Configuration

| Option | Required | Description |
|---|---|---|
| `endpoint` | yes | Bucket server URL, e.g. `https://<account>.r2.cloudflarestorage.com`. The router's service must point at the same URL. |
| `bucket` | yes | Bucket name. |
| `region` | no | Signing region. `auto` for R2, `us-east-1` (default) for most others. |
| `virtualHost` | no | Address the bucket as `<bucket>.<endpoint host>` instead of path style (`<endpoint>/<bucket>`). The service URL must then be the virtual-host URL. |
| `stripPrefix` | no | Removed from the request path first, e.g. `/sstate` for a `PathPrefix(`/sstate`)` router. Requests outside it get `404`. |
| `keyPrefix` | no | Put in front of every key, e.g. `scarthgap/`. |
| `accessKeyID` / `accessKeyIDFile` | yes | Bucket access key, inline or from a file. |
| `secretAccessKey` / `secretAccessKeyFile` | yes | Bucket secret key, inline or from a file. |
| `tokens` / `tokensFile` | yes | Accepted client tokens (at least 16 characters). The file holds one per line; `#` starts a comment. |

Use read-only bucket credentials. Give them `s3:ListBucket` on the bucket as
well, so a missing object returns `404` instead of `403`; BitBake falls back
to the next mirror either way.

Files are read when Traefik loads the configuration, so after changing a
token file, touch the dynamic configuration to reload it.

## Example

Static configuration (loading the plugin from a local checkout; Traefik
expects it under `./plugins-local/src/github.com/thomaskhub/traefik-plugin-s3-bucket`):

```yaml
experimental:
  localPlugins:
    s3token:
      moduleName: github.com/thomaskhub/traefik-plugin-s3-bucket
```

If the repository is public and listed in the Traefik plugin catalog, use
`experimental.plugins` with a `version` instead.

Dynamic configuration, one middleware per bucket:

```yaml
http:
  routers:
    sstate:
      rule: Host(`cache.example.com`) && PathPrefix(`/sstate`)
      middlewares: [sstate-r2]
      service: r2
    downloads:
      rule: Host(`cache.example.com`) && PathPrefix(`/downloads`)
      middlewares: [downloads-rustfs]
      service: rustfs

  middlewares:
    sstate-r2:
      plugin:
        s3token:
          endpoint: https://<account>.r2.cloudflarestorage.com
          region: auto
          bucket: yocto-sstate
          stripPrefix: /sstate
          accessKeyIDFile: /run/secrets/r2-access-key
          secretAccessKeyFile: /run/secrets/r2-secret-key
          tokensFile: /run/secrets/yocto-tokens
    downloads-rustfs:
      plugin:
        s3token:
          endpoint: https://rustfs.lan:9000
          bucket: yocto-downloads
          stripPrefix: /downloads
          accessKeyIDFile: /run/secrets/rustfs-access-key
          secretAccessKeyFile: /run/secrets/rustfs-secret-key
          tokensFile: /run/secrets/yocto-tokens

  services:
    r2:
      loadBalancer:
        servers:
          - url: https://<account>.r2.cloudflarestorage.com
    rustfs:
      loadBalancer:
        servers:
          - url: https://rustfs.lan:9000
```

## Yocto

In the build shell:

```sh
export YOCTO_CACHE_TOKEN=...   # from your CI secret store
export BB_ENV_PASSTHROUGH_ADDITIONS="$BB_ENV_PASSTHROUGH_ADDITIONS YOCTO_CACHE_TOKEN"
```

In `local.conf` or `site.conf`:

```
CACHE_URL = "https://cache.example.com"
SSTATE_MIRRORS ?= "file://.* ${CACHE_URL}/sstate/t/${YOCTO_CACHE_TOKEN}/PATH;downloadfilename=PATH"
PREMIRRORS:prepend = "\
    git://.*/.*   ${CACHE_URL}/downloads/t/${YOCTO_CACHE_TOKEN}/ \
    gitsm://.*/.* ${CACHE_URL}/downloads/t/${YOCTO_CACHE_TOKEN}/ \
    ftp://.*/.*   ${CACHE_URL}/downloads/t/${YOCTO_CACHE_TOKEN}/ \
    http://.*/.*  ${CACHE_URL}/downloads/t/${YOCTO_CACHE_TOKEN}/ \
    https://.*/.* ${CACHE_URL}/downloads/t/${YOCTO_CACHE_TOKEN}/ \
"
```

Tokens in the path appear in access logs; keep Traefik's access log off for
these routers or filter it if that matters.

## Development

```sh
go test -race ./...
yaegi test -v .      # how Traefik will run it
```
