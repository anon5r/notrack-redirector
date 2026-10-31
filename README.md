Anti-Tracking URL Redirector
====

Resolves affiliate / tracking redirect URLs **on the server side** and returns
the final destination with tracking parameters stripped off.

Two ways to use it:

- **Paste any tracking URL into the top page.** Works with any host — mail
  trackers, click wrappers, affiliate links. The resolved URL is only *shown*,
  never followed by the server, so this service never appears as a `Referer` on
  the destination. Optionally the page can open it for you (see below).
- **Point DNS of the tracking hostname at this service**, or call the explicit
  `/-/resolve` endpoint, to get a `302` to the cleaned destination. This path is
  restricted to an allowlist.


# How it works

1. The URL is checked: it must be an absolute `http(s)` URL that does not point
   at a loopback, private, CGNAT or link-local address.
2. The service fetches the URL itself and follows the redirect chain, up to 8
   hops, with no cookies and no forwarded headers. Both `Location` headers and
   HTML `<meta http-equiv="refresh">` are followed — several mail trackers
   (Sendinblue/Brevo among them) redirect only through the page body. The
   Cloudflare Worker additionally follows pages that answer `200` but forward
   right away: a `Refresh` response header (typically on an empty body), and
   JavaScript redirects (`location.href = "..."`, `location.replace("...")`,
   etc.) with a literal URL in an inline `<script>`. JavaScript redirects are
   only trusted on interstitial pages with almost no visible text, since
   guessing a destination out of a script on an ordinary page would be
   unreliable. A refresh that only reloads the same page is treated as the
   final destination. A URL that does not redirect is kept as-is, so pasting
   an ordinary link still strips its tracking parameters.
3. Tracking parameters (`utm_*`, `gclid`, Amazon `tag`, Rakuten `scid`, ...) are
   removed from the resolved URL.
4. The cleaned URL is shown on the top page, returned as JSON, or sent as a
   `302` — depending on the endpoint used. Every response carries
   `Referrer-Policy: no-referrer`.

Because the destination is taken from what the upstream service actually
returns — never from a URL written in a query parameter — this works for
tracking URLs that carry no destination URL in their parameters at all.

## Security notes

**The page never redirects and the server never returns a `302` for an
arbitrary host.** That is what keeps this from becoming an open redirector: you
cannot send someone a link to this service that lands them on a site of your
choosing. Two rules preserve that:

- The `302` paths (`/-/resolve` and the DNS-transition path) stay restricted to
  the hosts in `src/shared/rules.json`. **Never add a URL shortener** (`t.co`,
  `bit.ly`, ...) to that list: anyone can register an arbitrary destination
  there, which would turn those paths into an open redirector.
- "Open automatically" is stored per device in `localStorage` and **cannot be
  switched on through a URL parameter**, so a crafted link cannot make someone
  else's browser follow it. A test asserts this.
- Redirect hops pointing at loopback, private, CGNAT, link-local or `.local`
  addresses are rejected (SSRF protection). In the Go build this is enforced at
  dial time against the resolved IP as well.
- A `X-Notrack-Redirector: 1` header is attached to upstream requests. If the
  service receives a request carrying it, it answers `508 Loop Detected` instead
  of looping forever.


# Endpoints

| Path | Description |
| ---- | ----------- |
| `/` | URL input form (a static page). With `?u=<url>` the page resolves it through the API and shows the destination **without redirecting**. Any host is accepted. |
| `/api/resolve?u=<url>` | Resolution as JSON: `{"original", "destination", "hops"}`, or `{"error", "code"}` on failure. Any host is accepted. |
| `/api/trackers` | The allowlisted hosts, used to render the list on the page. |
| `/-/resolve?u=<tracking url>` | Returns a `302` to the cleaned destination. **Allowlisted hosts only.** |
| `/<tracking path>?<query>` | Returns a `302`. Used when the tracking hostname is pointed at this service by DNS or a Worker route. **Allowlisted hosts only.** |

`hops` and the route shown on the page are reduced to scheme + host + path; the
query strings of intermediate hops are not exposed.

## Referrer handling on the top page

The page is served with `Referrer-Policy: no-referrer` and a matching
`<meta name="referrer">`, and offers the destination three ways:

- **Copy the URL** — no navigation at all.
- **Open in a new tab** — `target="_blank" rel="noreferrer noopener"`.
- **Open in this tab** — `rel="noreferrer"`.

Both links suppress the `Referer` header, so the destination cannot see that the
visit came through this service. With **open automatically** enabled the page
navigates with `location.replace` once a result comes back, which leaves no
history entry and — because the page itself is `no-referrer` — sends no
`Referer` either.


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

All of these lists live in `src/shared/rules.json`, which both implementations
read: the Go build embeds it with `go:embed`, the Worker imports it at bundle
time. Edit that one file to change a rule.

Path patterns in it are regular expressions, so they must be valid in **both**
Go's `regexp` and JavaScript's `RegExp`.


# Shared UI

The page is a static site in `src/shared/ui` (`index.html`, `style.css`,
`app.js`) rather than server-rendered markup, so both implementations serve the
same files: the Go build embeds the directory with `go:embed`, the Worker
publishes it through [static assets](https://developers.cloudflare.com/workers/static-assets/).

The page renders nothing server-side — it calls `/api/resolve` and builds the
result with `textContent` and `setAttribute`, never `innerHTML`. Error wording
lives only in `app.js`, keyed by the `code` the API returns
(`unsupported_url`, `invalid_url`, `blocked_destination`, `too_many_hops`,
`upstream_error`).

The page is built for phone use: 48px tap targets, a 16px input (so iOS does not
zoom on focus), a **paste and resolve** button, and a web app manifest with a
`share_target`, so on Android it can be installed and receive URLs straight from
the system share sheet. Shared text often arrives as "title + URL", so the first
`http(s)` URL is extracted from it.

Both implementations attach the same headers to those files —
`Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and a CSP of
`default-src 'none'` with `script-src` limited to `'self'` and no
`unsafe-inline`. The Worker uses `run_worker_first` so that it can set them
itself rather than relying on a `_headers` file.


# Behind an authenticating proxy

The service works behind Cloudflare Access (or a similar proxy), which is the
recommended way to run it — see the security notes above.

Two things are needed for that, both already in place:

- `style-src`, `manifest-src`, `connect-src` and `form-action` allow
  `https://*.cloudflareaccess.com`. CSP checks the *redirect target*, not just
  the request URL, so an expired session redirecting to the login screen is
  otherwise blocked outright — including plain form submissions.
- The page calls the API with `redirect: "manual"`, so a login redirect comes
  back as an opaque response instead of failing CORS on the login origin. The
  page detects it and offers a reload button to re-authenticate, rather than
  reporting it as a resolution failure.

If a content blocker rewrites the page's CSP (AdGuard does this, adding
`local.adguard.org` to the directives), the Access login screen can still be
blocked. Allowlist the service's hostname in the blocker if that happens.


# How to Build

## Go

```shell
$ go build -o dist/track-redir ./src
```

## Docker

```shell
$ docker build -t track-redir:latest -f docker/golang/Dockerfile .
```

### Running on Docker container

```shell
$ docker run --rm --name redirgo -p 9090:9000 track-redir
```

The runtime image is `alpine` with `ca-certificates`, which the upstream HTTPS
fetch needs.


# Test

```shell
$ go test ./src
$ npm --prefix src/cloudfare-worker test
```


# Deploy (Cloudflare Workers)

```shell
$ cd src/cloudfare-worker
$ CLOUDFLARE_ACCOUNT_ID=<account id> npx wrangler deploy
```

The Worker is named `anti-tracker` in `wrangler.jsonc`; deploying replaces that
existing Worker rather than creating a new one.

`CLOUDFLARE_ACCOUNT_ID` is only needed when the authenticated user has more
than one account; it is kept out of `wrangler.jsonc` on purpose.

Set `UPSTREAM_HOST_MAP` in `wrangler.jsonc` (or as a secret) when tracking
hostnames are routed to the Worker; see Configuration above. Workers cannot dial
raw IP addresses, so the override value there must be a hostname.


# Debug

## Go

```shell
$ go run ./src
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


# Hosts allowed on the `302` paths

Any URL can be resolved through the page and `/api/resolve`. The list below only
governs the paths that issue a real redirect.

- `https://px.a8.net/svt/...`
- `https://hb.afl.rakuten.co.jp/ichiba/...`
- `https://hb.afl.rakuten.co.jp/hgc/...`
- `https://hb.afl.rakuten.co.jp/hsc/...`
- `https://ck.jp.ap.valuecommerce.com/servlet/referral?...`
- `https://af.moshimo.com/af/c/click?...`
- `https://t.afi-b.com/...`
- `https://click.linksynergy.com/...`


# Layout

```
go.mod                          Go module for the Go build
src/main.go                     Go implementation
src/main_test.go
src/shared/rules.json           Allowlist and tracking parameters, shared by both
src/shared/ui/                  Static page shared by both (index.html,
                                style.css, app.js, icon.svg,
                                manifest.webmanifest)
src/cloudfare-worker/worker.js  Cloudflare Worker implementation
src/cloudfare-worker/wrangler.jsonc
src/lambda/nodejs/main.js       Stub, not implemented
docker/                         Container build for the Go implementation
```
