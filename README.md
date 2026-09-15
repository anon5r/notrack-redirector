Anti-Tracking URL Redirector
====

Resolves affiliate / tracking redirect URLs **on the server side** and returns
the final destination with tracking parameters stripped off.

Two ways to use it:

- **Paste a URL into the top page.** The resolved URL is only *shown*, never
  followed, so this service never appears as a `Referer` on the destination.
- **Point DNS of the tracking hostname at this service**, or call the explicit
  `/-/resolve` endpoint, to get a `302` to the cleaned destination.


# How it works

1. The incoming request is matched against an allowlist of known affiliate /
   tracking services (host + path). Anything else is rejected.
2. The service fetches the tracking URL itself and follows the redirect chain
   (`Location` headers only, up to 8 hops, no cookies, no forwarded headers).
3. Tracking parameters (`utm_*`, `gclid`, Amazon `tag`, Rakuten `scid`, ...) are
   removed from the resolved URL.
4. The cleaned URL is shown on the top page, returned as JSON, or sent as a
   `302` — depending on the endpoint used. Every response carries
   `Referrer-Policy: no-referrer`.

Because the destination is taken from what the upstream service actually
returns — never from a URL written in a query parameter — this service **cannot
be turned into an open redirector** by crafting a request such as
`/svt/ejp?a8mat=https://phishing.example/`. It also works for tracking URLs that
carry no destination URL in their parameters at all.

## Security notes

- Only hosts listed in `trackerRules` (Go) / `TRACKER_RULES` (Worker) are
  fetched. **Never add a URL shortener** (`t.co`, `bit.ly`, ...) to that list:
  anyone can register an arbitrary destination there, which would reintroduce
  the open redirector problem.
- Redirect hops pointing at loopback, private, CGNAT, link-local or `.local`
  addresses are rejected (SSRF protection). In the Go build this is enforced at
  dial time against the resolved IP as well.
- A `X-Notrack-Redirector: 1` header is attached to upstream requests. If the
  service receives a request carrying it, it answers `508 Loop Detected` instead
  of looping forever.


# Endpoints

| Path | Description |
| ---- | ----------- |
| `/` | URL input form. With `?u=<tracking url>` it shows the resolved destination **without redirecting**. |
| `/api/resolve?u=<tracking url>` | Same resolution as JSON: `{"original", "destination", "hops"}`. |
| `/-/resolve?u=<tracking url>` | Returns a `302` to the cleaned destination. |
| `/<tracking path>?<query>` | Returns a `302`. Used when the tracking hostname is pointed at this service by DNS or a Worker route. |

`hops` and the route shown on the page are reduced to scheme + host + path; the
query strings of intermediate hops are not exposed.

## Referrer handling on the top page

The page is served with `Referrer-Policy: no-referrer` and a matching
`<meta name="referrer">`, and offers the destination three ways:

- **Copy the URL** — no navigation at all.
- **Open in a new tab** — `target="_blank" rel="noreferrer noopener"`.
- **Open in this tab** — `rel="noreferrer"`.

Both links suppress the `Referer` header, so the destination cannot see that the
visit came through this service.


# Configuration

| Variable | Description |
| -------- | ----------- |
| `LISTEN_ADDR` | Listen address for the Go build. Default `:9000`. |
| `UPSTREAM_HOST_MAP` | `host=addr[,host=addr]`. Overrides where an upstream host is actually contacted (`203.0.113.10` or `203.0.113.10:8080`). Required when DNS for the tracking host points back at this service, otherwise the upstream fetch loops onto itself. |
| `ALLOW_PRIVATE_UPSTREAM` | Go only. `1` disables the private-address dial guard. Use for local testing only. |

The Cloudflare Worker reads `UPSTREAM_HOST_MAP` from its environment bindings;
there the override value is a hostname (optionally `host:port`), since Workers
cannot dial raw IP addresses.


# What gets stripped

- Global exact matches: `gclid`, `fbclid`, `msclkid`, `yclid`, `ttclid`, `_ga`,
  `mkt_tok`, ... 
- Global prefixes: `utm_`, `mtm_`, `pk_`, `piwik_`, `hsa_`, `trk_`, ...
- Host-scoped names, for parameters that are ambiguous in general:
  Amazon (`tag`, `linkCode`, `ascsubtag`, `ref`, ...), Rakuten (`scid`, `l-id`,
  ...), Yahoo, YouTube, X/Twitter.

The Go and Worker implementations keep these lists — and the page markup —
separately, since the Go build is a single file with no module setup.
**Update both when changing a rule.**


# How to Build

## Go

```shell
$ go build -o dist/track-redir src/main/main.go
```

## Docker

```shell
$ docker build -t track-redir:latest -f docker/golang/Dockerfile .
```

### Running on Docker container

```shell
$ docker run --rm --name redirgo -p 9090:9000 track-redir
```


# Test

```shell
$ go test src/main/main.go src/main/main_test.go
$ npm --prefix src/cloudfare-worker test
```


# Deploy (Cloudflare Workers)

```shell
$ cd src/cloudfare-worker
$ CLOUDFLARE_ACCOUNT_ID=<account id> npx wrangler deploy
```

`CLOUDFLARE_ACCOUNT_ID` is only needed when the authenticated user has more
than one account; it is kept out of `wrangler.jsonc` on purpose.

Set `UPSTREAM_HOST_MAP` in `wrangler.jsonc` (or as a secret) when tracking
hostnames are routed to the Worker; see Configuration above. Workers cannot dial
raw IP addresses, so the override value there must be a hostname.


# Debug

## Go

```shell
$ go run src/main/main.go
```

Then open <http://localhost:9000/> and paste a tracking URL into the form, or:

```shell
$ curl 'http://localhost:9000/api/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3D...'
$ curl -i 'http://localhost:9000/-/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3D...'
```

To exercise the DNS-transition path, point the tracking hostname at `127.0.0.1`
in `/etc/hosts`.

## Cloudflare Worker

```shell
$ npm --prefix src/cloudfare-worker run dev
```


# Supported track URL patterns

- `https://px.a8.net/svt/...`
- `https://hb.afl.rakuten.co.jp/ichiba/...`
- `https://hb.afl.rakuten.co.jp/hgc/...`
- `https://hb.afl.rakuten.co.jp/hsc/...`
- `https://ck.jp.ap.valuecommerce.com/servlet/referral?...`
- `https://af.moshimo.com/af/c/click?...`
- `https://t.afi-b.com/...`
- `https://click.linksynergy.com/...`
