import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    errorCode,
    metaRefreshTarget,
    parseResolvableURL,
    parseTrackerURL,
    handleRequest,
    hopLabels,
    isNonPublicAddress,
    isTrackerURL,
    parseHostMap,
    resolveDestination,
    stripTrackingParams,
    targetURL,
    validateHopURL,
} from "./worker.js";

test("isTrackerURL は allowlist のみを受け付ける", () => {
    const cases = [
        ["https://px.a8.net/svt/ejp?a8mat=abc", true],
        ["https://px.a8.net/other", false],
        ["https://hb.afl.rakuten.co.jp/ichiba/abc.def/", true],
        ["https://ck.jp.ap.valuecommerce.com/servlet/referral?sid=1", true],
        ["https://t.afi-b.com/anything", true],
        ["https://evil.example/svt/ejp?a8mat=abc", false],
        ["https://px.a8.net.evil.example/svt/ejp", false],
    ];
    for (const [raw, want] of cases) {
        assert.equal(isTrackerURL(new URL(raw)), want, raw);
    }
});

test("targetURL はパラメータの URL ではなくリクエスト自体を対象にする", () => {
    const target = targetURL(new URL("https://px.a8.net/svt/ejp?a8mat=https%3A%2F%2Fphishing.example%2F"));
    assert.equal(target.hostname, "px.a8.net");

    assert.throws(() => targetURL(new URL("https://redirector.example/?url=https://phishing.example/")), {
        status: 404,
    });
    assert.throws(() => targetURL(new URL("https://redirector.example/-/resolve?u=https%3A%2F%2Fphishing.example%2F")), {
        status: 404,
    });

    const viaEndpoint = targetURL(
        new URL("https://redirector.example/-/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc"),
    );
    assert.equal(viaEndpoint.toString(), "https://px.a8.net/svt/ejp?a8mat=abc");
});

test("validateHopURL は内部宛先を拒否する", () => {
    for (const raw of [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "https://printer.local/",
    ]) {
        assert.throws(() => validateHopURL(new URL(raw)), { status: 403 }, raw);
    }
    assert.doesNotThrow(() => validateHopURL(new URL("https://example.com/item")));
});

test("isNonPublicAddress", () => {
    const cases = {
        "8.8.8.8": false,
        "example.com": false,
        "127.0.0.1": true,
        "10.1.2.3": true,
        "172.16.0.1": true,
        "192.168.1.1": true,
        "169.254.169.254": true,
        "100.64.0.1": true,
        "[::1]": true,
        "[fd00::1]": true,
    };
    for (const [host, want] of Object.entries(cases)) {
        assert.equal(isNonPublicAddress(host), want, host);
    }
});

test("stripTrackingParams", () => {
    const cases = [
        ["https://example.com/p?id=1&utm_source=a8&gclid=xyz", "https://example.com/p?id=1"],
        ["https://www.amazon.co.jp/dp/B0000?tag=aff-22&linkCode=osi&psc=1", "https://www.amazon.co.jp/dp/B0000"],
        ["https://item.rakuten.co.jp/shop/item/?scid=af_link&l-id=top", "https://item.rakuten.co.jp/shop/item/"],
        // ホスト固有パラメータは他ホストでは消さない。
        ["https://example.com/search?tag=go&ref=top", "https://example.com/search?tag=go&ref=top"],
        ["https://example.com/p", "https://example.com/p"],
    ];
    for (const [raw, want] of cases) {
        assert.equal(stripTrackingParams(new URL(raw)).toString(), want, raw);
    }
});

test("parseHostMap", () => {
    const got = parseHostMap(" PX.A8.NET=127.0.0.1:9001 , broken , example.com=127.0.0.1:9002 ");
    assert.equal(got.size, 2);
    assert.equal(got.get("px.a8.net"), "127.0.0.1:9001");
    assert.equal(got.get("example.com"), "127.0.0.1:9002");
});

/** fetch をスタブし、パス -> レスポンス定義でリダイレクトチェーンを模擬する。 */
function stubFetch(routes) {
    const original = globalThis.fetch;
    globalThis.fetch = async (input) => {
        const url = new URL(input);
        const route = routes[url.pathname];
        if (!route) {
            return new Response(null, { status: 404 });
        }
        if (route.location) {
            return new Response(null, { status: 302, headers: { Location: route.location } });
        }
        if (route.html) {
            return new Response(route.html, {
                status: 200,
                headers: { "Content-Type": "text/html; charset=utf-8" },
            });
        }
        return new Response(null, { status: route.status || 200 });
    };
    return () => {
        globalThis.fetch = original;
    };
}

test("resolveDestination は上流の Location のみを根拠にする", async (t) => {
    const restore = stubFetch({
        "/svt/ejp": { location: "https://example.com/hop" },
        "/hop": { location: "https://example.com/final?id=1&utm_source=a8" },
        "/final": { status: 200 },
    });
    t.after(restore);

    const result = await resolveDestination(
        new URL("https://px.a8.net/svt/ejp?a8mat=https%3A%2F%2Fphishing.example%2F"),
        new Map(),
    );
    assert.equal(stripTrackingParams(result.final).toString(), "https://example.com/final?id=1");
    assert.deepEqual(hopLabels(result.hops), ["https://example.com/hop", "https://example.com/final"]);
});

test("resolveDestination は内部宛先へのホップを拒否する", async (t) => {
    const restore = stubFetch({ "/svt/ejp": { location: "http://169.254.169.254/latest/meta-data/" } });
    t.after(restore);

    await assert.rejects(() => resolveDestination(new URL("https://px.a8.net/svt/ejp"), new Map()), (err) => {
        assert.equal(err.status, 403);
        assert.equal(errorCode(err), "blocked_destination");
        return true;
    });
});

test("resolveDestination はホップ上限で打ち切る", async (t) => {
    const restore = stubFetch({
        "/svt/ejp": { location: "https://example.com/loop" },
        "/loop": { location: "https://example.com/loop" },
    });
    t.after(restore);

    await assert.rejects(() => resolveDestination(new URL("https://px.a8.net/svt/ejp"), new Map()), {
        status: 508,
    });
});

test("resolveDestination はリダイレクトしない URL もそのまま返す", async (t) => {
    const restore = stubFetch({ "/item": { status: 200 } });
    t.after(restore);

    const result = await resolveDestination(new URL("https://example.com/item?id=1&utm_source=mail"), new Map());
    assert.equal(result.hops.length, 0);
    assert.equal(stripTrackingParams(result.final).toString(), "https://example.com/item?id=1");
});

test("parseResolvableURL は allowlist 外のホストも受け付ける", () => {
    for (const raw of [
        "https://links1.cloudflare.com/s/c/abcdef",
        "http://r.mail-sib.craft.do/mk/cl/f/sh/token",
    ]) {
        assert.doesNotThrow(() => parseResolvableURL(raw), raw);
    }

    for (const raw of [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "not a url",
    ]) {
        assert.throws(() => parseResolvableURL(raw), raw);
    }
});

test("parseTrackerURL は allowlist を要求し続ける", () => {
    assert.doesNotThrow(() => parseTrackerURL("https://px.a8.net/svt/ejp?a8mat=abc"));
    assert.throws(() => parseTrackerURL("https://links1.cloudflare.com/s/c/abcdef"), {
        code: "unsupported_url",
    });
});

/** トップページ / API テスト用に単純なリダイレクトチェーンを用意する。 */
function stubUpstream() {
    return stubFetch({
        "/svt/ejp": { location: "https://example.com/final?id=1&utm_source=a8" },
        "/final": { status: 200 },
    });
}

/** 実際の共有 UI を配信する ASSETS バインディングのスタブ。 */
const env = {
    ASSETS: {
        async fetch(request) {
            const path = new URL(request.url).pathname;
            const name = path === "/" ? "index.html" : path.replace(/^\//, "");
            try {
                const body = await readFile(new URL(`../shared/ui/${name}`, import.meta.url), "utf8");
                return new Response(body, { status: 200 });
            } catch {
                return new Response(null, { status: 404 });
            }
        },
    },
};

function get(target, headers = {}) {
    return handleRequest(new Request(target, { headers }), env);
}

test("共有 UI を配信する", async (t) => {
    t.after(stubUpstream());

    for (const path of ["/", "/style.css", "/app.js"]) {
        const response = await get(`https://redirector.example${path}`);
        assert.equal(response.status, 200, path);
        assert.equal(response.headers.get("Referrer-Policy"), "no-referrer", path);
        assert.match(response.headers.get("Content-Security-Policy"), /script-src 'self'/, path);
    }

    const index = await (await get("https://redirector.example/")).text();
    assert.match(index, /name="u"/);
    assert.match(index, /\/app\.js/);
});

test("トップページはリダイレクトしない", async (t) => {
    t.after(stubUpstream());

    const response = await get("https://redirector.example/?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc");
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Location"), null);
});

test("未知のパスは 404 を返す", async (t) => {
    t.after(stubUpstream());

    const response = await get("https://redirector.example/does-not-exist");
    assert.equal(response.status, 404);
});

test("/api/trackers は対応サービス一覧を返す", async (t) => {
    t.after(stubUpstream());

    const response = await get("https://redirector.example/api/trackers");
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.ok(body.trackers.includes("px.a8.net"));
});

test("/api/resolve は JSON を返す", async (t) => {
    t.after(stubUpstream());

    const response = await get("https://redirector.example/api/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc");
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.destination, "https://example.com/final?id=1");
    assert.deepEqual(body.hops, ["https://example.com/final"]);

    const bad = await get("https://redirector.example/api/resolve?u=http%3A%2F%2F127.0.0.1%2Fadmin");
    assert.equal(bad.status, 403);
    assert.equal((await bad.json()).code, "blocked_destination");
});

test("トラッキングホスト宛のリクエストは従来どおり 302 を返す", async (t) => {
    t.after(stubUpstream());

    const response = await get("https://px.a8.net/svt/ejp?a8mat=abc");
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("Location"), "https://example.com/final?id=1");
});

test("ループガードヘッダ付きのリクエストは 508 を返す", async () => {
    const response = await get("https://px.a8.net/svt/ejp?a8mat=abc", { "X-Notrack-Redirector": "1" });
    assert.equal(response.status, 508);
});

test("app.js が参照する要素 ID が index.html に存在する", async () => {
    const uiPath = (name) => new URL(`../shared/ui/${name}`, import.meta.url);
    const [html, script] = await Promise.all([
        readFile(uiPath("index.html"), "utf8"),
        readFile(uiPath("app.js"), "utf8"),
    ]);

    const referenced = [...script.matchAll(/getElementById\("([^"]+)"\)/g)].map((m) => m[1]);
    assert.ok(referenced.length > 0, "app.js does not reference any element");

    const defined = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    for (const id of referenced) {
        assert.ok(defined.has(id), `index.html is missing id="${id}"`);
    }
});

test("index.html が参照する静的ファイルが存在する", async () => {
    const html = await readFile(new URL("../shared/ui/index.html", import.meta.url), "utf8");
    const refs = [...html.matchAll(/(?:href|src)="\/([^"]+)"/g)].map((m) => m[1]);

    assert.ok(refs.includes("app.js"));
    assert.ok(refs.includes("style.css"));
    assert.ok(refs.includes("manifest.webmanifest"));

    for (const ref of refs) {
        await readFile(new URL(`../shared/ui/${ref}`, import.meta.url));
    }
});

test("manifest の share_target が app.js の読み取るパラメータと一致する", async () => {
    const uiPath = (name) => new URL(`../shared/ui/${name}`, import.meta.url);
    const [manifest, script] = await Promise.all([
        readFile(uiPath("manifest.webmanifest"), "utf8").then(JSON.parse),
        readFile(uiPath("app.js"), "utf8"),
    ]);

    for (const name of Object.values(manifest.share_target.params)) {
        if (name === "title") {
            continue;
        }
        assert.match(script, new RegExp(`params\\.get\\("${name}"\\)`), `app.js does not read "${name}"`);
    }
});

test("自動で開く設定は URL パラメータから有効化できない", async () => {
    const script = await readFile(new URL("../shared/ui/app.js", import.meta.url), "utf8");

    // 端末に保存した設定以外から autoOpen を立てる経路があってはならない。
    // URL で指定できると「開くだけで任意の URL へ飛ぶリンク」を他人に送れてしまう。
    const assignments = [...script.matchAll(/autoOpen\.checked\s*=\s*([^;]+);/g)].map((m) => m[1].trim());
    assert.deepEqual(assignments, ["readAutoOpen()"]);
});

test("metaRefreshTarget", () => {
    const cases = [
        [
            `<html><body><noscript><meta http-equiv="refresh" content="0.0;https://www.craft.do/download"></noscript></body></html>`,
            "https://www.craft.do/download",
        ],
        [`<meta http-equiv="Refresh" content="5; URL=https://example.com/next">`, "https://example.com/next"],
        [`<meta content="0;url=/relative" http-equiv='refresh'>`, "/relative"],
        [`<meta name="description" content="0;url=https://evil.example/">`, ""],
        [`<script>top.location='https://example.com/js'</script>`, ""],
        [`<html><body>hello</body></html>`, ""],
    ];
    for (const [html, want] of cases) {
        assert.equal(metaRefreshTarget(html), want, html.slice(0, 60));
    }
});

test("resolveDestination は meta refresh も追跡する", async (t) => {
    const restore = stubFetch({
        "/mk/cl": {
            html: `<html><body><noscript>` +
                `<meta http-equiv="refresh" content="0.0;https://example.com/download?utm_source=mail">` +
                `</noscript></body></html>`,
        },
        "/download": { status: 200 },
    });
    t.after(restore);

    const result = await resolveDestination(new URL("https://tracker.example/mk/cl"), new Map());
    assert.equal(stripTrackingParams(result.final).toString(), "https://example.com/download");
    assert.equal(result.hops.length, 1);
});

test("resolveDestination は meta refresh の危険な宛先を拒否する", async (t) => {
    const restore = stubFetch({
        "/mk/cl": { html: `<meta http-equiv="refresh" content="0;url=http://169.254.169.254/latest/meta-data/">` },
    });
    t.after(restore);

    await assert.rejects(() => resolveDestination(new URL("https://tracker.example/mk/cl"), new Map()), {
        status: 403,
    });
});
