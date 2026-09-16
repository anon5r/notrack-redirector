import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
    errorCode,
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

test("resolveDestination はリダイレクトしない上流を拒否する", async (t) => {
    const restore = stubFetch({ "/svt/ejp": { status: 200 } });
    t.after(restore);

    await assert.rejects(() => resolveDestination(new URL("https://px.a8.net/svt/ejp"), new Map()), {
        status: 502,
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

    const bad = await get("https://redirector.example/api/resolve?u=https%3A%2F%2Fphishing.example%2F");
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).code, "unsupported_url");
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
