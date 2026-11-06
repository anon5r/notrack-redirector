Anti-Tracking URL Redirector
====

Resolves affiliate / tracking redirect URLs **on the server side** and returns
the final destination with tracking parameters and affiliate codes stripped
off. It runs on [Cloudflare Workers](https://developers.cloudflare.com/workers/).

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
   HTML `<meta http-equiv="refresh">` (with character references such as `&amp;`
   decoded) are followed — several mail trackers (Sendinblue/Brevo among them)
   redirect only through the page body. Pages that answer `200` but forward
   right away are followed too: a `Refresh` response header (typically on an
   empty body), and JavaScript redirects (`location.href = "..."`, `location.replace("...")`,
   etc.) with a literal URL in an inline `<script>`. JavaScript redirects are
   only trusted on interstitial pages with almost no visible text, since
   guessing a destination out of a script on an ordinary page would be
   unreliable. A refresh that only reloads the same page is treated as the
   final destination. A URL that does not redirect is kept as-is, so pasting
   an ordinary link still strips its tracking parameters.
3. Tracking parameters (`utm_*`, `gclid`, Amazon `pd_rd_*`, ...) and affiliate
   codes (Amazon `tag`, Rakuten `scid=af_*`, `irclickid`, ...) are removed from
   the resolved URL. Each of the two can be switched off; see
   [What gets stripped](#what-gets-stripped).
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
choosing. These rules preserve that:

- The `302` paths (`/-/resolve` and the DNS-transition path) stay restricted to
  the `trackers` in `src/shared/rules.mjs`. **Never add a URL shortener** (`t.co`,
  `bit.ly`, ...) to that list: anyone can register an arbitrary destination
  there, which would turn those paths into an open redirector.
- "Open automatically" is stored per device in `localStorage` and **cannot be
  switched on through a URL parameter**, so a crafted link cannot make someone
  else's browser follow it. A test asserts this.
- Redirect hops pointing at loopback, private, CGNAT, link-local or `.local`
  addresses are rejected (SSRF protection).
- A `X-Notrack-Redirector: 1` header is attached to upstream requests. If the
  service receives a request carrying it, it answers `508 Loop Detected` instead
  of looping forever.


# Endpoints

| Path | Description |
| ---- | ----------- |
| `/` | URL input form (a static page). With `?u=<url>` the page resolves it through the API and shows the destination **without redirecting**. Any host is accepted. |
| `/api/resolve?u=<url>` | Resolution as JSON: `{"original", "destination", "hops"}`, or `{"error", "code"}` on failure. Any host is accepted. Accepts the strip options below. |
| `/api/trackers` | The allowlisted hosts, used to render the list on the page. |
| `/-/resolve?u=<tracking url>` | Returns a `302` to the cleaned destination. **Allowlisted hosts only.** Accepts the strip options below. |
| `/<tracking path>?<query>` | Returns a `302`. Used when the tracking hostname is pointed at this service by DNS or a Worker route. **Allowlisted hosts only.** |

Strip options (both default to on):

| Parameter | Description |
| --------- | ----------- |
| `strip_tracking=0` | Keep tracking parameters. |
| `strip_affiliate=0` | Keep affiliate codes, so the referrer of the link still gets credited. |

The DNS-transition path always strips both, since its query string belongs to
the upstream URL.

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
| `UPSTREAM_HOST_MAP` | `host=origin[,host=origin]`. Overrides where an upstream host is actually contacted. Required when the tracking hostname is routed to this Worker, otherwise the upstream fetch loops onto itself. The override is a hostname (optionally `host:port`), since Workers cannot dial raw IP addresses. |

It is read from the Worker's environment bindings (`vars` in `wrangler.jsonc`,
or a secret).


# What gets stripped

Parameters are split into two kinds, each of which can be switched off on the
page (stored per device) or with the strip options above.

**Tracking** — analytics and ad-click measurement:

- Global exact matches: `gclid`, `fbclid`, `msclkid`, `yclid`, `ttclid`,
  `_ga`, `mkt_tok`, ...
- Global prefixes: `utm_`, `mtm_`, `pk_`, `piwik_`, `hsa_`, `trk_`, ...
- Host-scoped names, for parameters that are ambiguous in general: Amazon
  (`ref`, `qid`, `pd_rd_*`, `pf_rd_*`, `hv*`, and `/ref=...` in the path),
  Rakuten (`l-id`, `iasid`, `s-id`, non-affiliate `scid`, ...), Temu (`_x_*`,
  `_p_*`, `_oak_*`, `refer_page_*`, ...), DMM (`dmmref`, `i3_ref`, `i3_ord`),
  AliExpress, eBay, Apple, Yahoo, YouTube, X/Twitter.

- Decided by combination (`markers`): AD EBiS's `argument` and `dmai`, only
  when `dmai` is present, since `argument` alone is a common name.
- Everything a page does not need, on Amazon, Rakuten Ichiba / Books, Temu,
  DMM / FANZA and DLsite. For these sites `keepOnly` lists the parameters
  that pages actually use (search terms, filters, sort order, page number,
  variant, seller, language, ...); any other parameter counts as tracking.
  Pages that require their parameters — sign-in, cart, checkout, DMM's age
  check — are excluded by `exceptPaths`.

**Affiliate** — codes that credit whoever shared the link:

- Global: `aff_*`, A8.net `a8`, ValueCommerce `vc_lpp`, afb `abm`, moshimo
  `rd_code`, Impact `irclickid` /
  `irgwc`, CJ `cjevent`, Awin `awc`, ShareASale `sscid`, Rakuten Advertising
  `ranMID` / `ranEAID` / `ranSiteID`, Admitad `admitad_uid`, Tradedoubler
  `tduid`, Post Affiliate Pro `a_aid` / `a_bid`, AvantLink `avad`,
  FirstPromoter `fpr`, PartnerStack `ps_partner_key` / `ps_xid`, Refersion
  `rfsn`, Skimlinks `xcust`, plus sub-IDs (`sharedid`, `cjdata`, `clickref`,
  `afftrack`).
- Host-scoped: Amazon (`tag`, `linkCode`, `linkId`, `ascsubtag`, `creative`,
  `creativeASIN`, `camp`, ...), Rakuten `rafcid`, Temu share referral
  (`refer_share_*`), AliExpress (`sk`, `dp`, `af`, `terminal_id`, ...), eBay
  Partner Network (`campid`, `mkcid`, `mkrid`, `mkevt`, `toolid`, `customid`),
  Apple `at`, Booking.com (`aid`, `label`), Best Service `aid`.
- Decided by value (`markers`): when `utm_medium` contains `affiliate`, all
  `utm_*` are treated as affiliate codes. DMM (`utm_medium=dmm_affiliate`) and
  DLsite (`utm_medium=affiliate`) put the affiliate ID in `utm_source` this
  way. On Rakuten, `scid` / `sc2id` starting with `af_` are affiliate codes, and
  on Yahoo! Shopping so is `sc_e` starting with `afvc` (ValueCommerce).

A parameter that matches both kinds counts as affiliate, so keeping affiliate
codes keeps it even while tracking parameters are stripped. That also holds
on `keepOnly` sites: Amazon's `tag` and `linkCode` stay when affiliate codes
are kept, although they are not on the list of parameters pages need.

The lists are based on [ClearURLs](https://github.com/ClearURLs/Rules), the
[AdGuard URL Tracking filter](https://github.com/AdguardTeam/AdguardFilters/tree/master/TrackParamFilter),
the [Affiliate Tracking Parameter Reference](https://afterlink.io/parameters),
plus the actual redirect chains of DMM and DLsite affiliate links.

All of these lists, together with the `302` allowlist, live in
`src/shared/rules.mjs`. It is a plain ES module, so each rule can carry a
comment with its source; the Worker imports it and wrangler bundles it in at
deploy time. Edit that one file to change a rule.

The allowlist `paths`, the host rules' `pathPatterns` and the markers'
`pattern` are written as strings and compiled with `RegExp`. `pathPatterns` and
`pattern` are matched case-insensitively.


# UI

The page is a static site in `src/shared/ui` (`index.html`, `style.css`,
`app.js`) rather than server-rendered markup. The Worker publishes it through
[static assets](https://developers.cloudflare.com/workers/static-assets/).

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

The Worker attaches these headers to those files —
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


# Test

```shell
$ npm --prefix src/cloudflare-worker install
$ npm --prefix src/cloudflare-worker test
```

The tests run on Node's built-in test runner and stub `fetch`, so they need no
network access.


# Deploy (Cloudflare Workers)

```shell
$ cd src/cloudflare-worker
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

```shell
$ npm --prefix src/cloudflare-worker run dev
```

Then open <http://localhost:8787/> and paste a tracking URL into the form, or:

```shell
$ curl 'http://localhost:8787/api/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3D...'
$ curl 'http://localhost:8787/api/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3D...&strip_affiliate=0'
$ curl -i 'http://localhost:8787/-/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3D...'
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
src/cloudflare-worker/worker.js       Cloudflare Worker implementation
src/cloudflare-worker/worker.test.js
src/cloudflare-worker/wrangler.jsonc
src/shared/rules.mjs                 302 allowlist and parameters to strip
src/shared/ui/                       Static page (index.html, style.css,
                                     app.js, icon.svg, manifest.webmanifest)
src/lambda/nodejs/main.js            Stub, not implemented
```
