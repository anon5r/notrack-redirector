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
    scriptRedirectTarget,
    stripParams,
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

test("stripParams は既定でトラッキングとアフィリエイトの両方を除去する", () => {
    const cases = [
        ["https://example.com/p?id=1&utm_source=a8&gclid=xyz", "https://example.com/p?id=1"],
        ["https://www.amazon.co.jp/dp/B0000?tag=aff-22&linkCode=osi&psc=1", "https://www.amazon.co.jp/dp/B0000"],
        ["https://www.amazon.de/dp/B0000?tag=aff-21&pd_rd_w=abc", "https://www.amazon.de/dp/B0000"],
        // Amazon はパスにも ref= の計測情報を埋め込む。
        ["https://www.amazon.co.jp/dp/B0000/ref=sr_1_1?qid=1&tag=aff-22", "https://www.amazon.co.jp/dp/B0000"],
        ["https://item.rakuten.co.jp/shop/item/?scid=af_link&l-id=top", "https://item.rakuten.co.jp/shop/item/"],
        [
            "https://www.dlsite.com/home/work/=/product_id/RJ01.html/?utm_medium=affiliate&utm_source=aff1",
            "https://www.dlsite.com/home/work/=/product_id/RJ01.html/",
        ],
        ["https://www.temu.com/g.html?goods_id=1&sku_id=2&_x_ads_channel=g&refer_share_id=a", "https://www.temu.com/g.html?goods_id=1&sku_id=2"],
        ["https://shop.example/p?id=1&irclickid=z&aff_sub=1&cjevent=c", "https://shop.example/p?id=1"],
        // 許可リストの ASP が広告主の LP に付けるクリック識別子。
        ["https://shop.example/lp?id=1&a8=x&vc_lpp=y&abm=z&rd_code=w&ranMID=1", "https://shop.example/lp?id=1"],
        // もしもアフィリエイト経由の Amazon は Amazon のアソシエイトタグになる。
        [
            "https://www.amazon.co.jp/dp/4167158043?tag=maftracking178367-22&linkCode=ure&creative=6339",
            "https://www.amazon.co.jp/dp/4167158043",
        ],
        ["https://www.booking.com/hotel/jp/x.html?aid=123&label=blog", "https://www.booking.com/hotel/jp/x.html"],
        ["https://store.shopping.yahoo.co.jp/s/i.html?sc_e=afvc_shp_1", "https://store.shopping.yahoo.co.jp/s/i.html"],
        // ホスト固有パラメータは他ホストでは消さない。
        ["https://example.com/search?tag=go&ref=top", "https://example.com/search?tag=go&ref=top"],
        ["https://example.com/ref=keep/p", "https://example.com/ref=keep/p"],
        ["https://example.com/p", "https://example.com/p"],
    ];
    for (const [raw, want] of cases) {
        assert.equal(stripParams(new URL(raw)).toString(), want, raw);
    }
});

test("stripParams はアフィリエイトを残してトラッキングだけを除去できる", () => {
    const options = { tracking: true, affiliate: false };
    const cases = [
        [
            "https://www.amazon.co.jp/dp/B0000/ref=sr_1_1?tag=aff-22&linkCode=osi&psc=1&pd_rd_w=x",
            "https://www.amazon.co.jp/dp/B0000?tag=aff-22&linkCode=osi",
        ],
        // DMM / DLsite は utm_* にアフィリエイト ID を入れるため、まとめて残す。
        [
            "https://www.dlsite.com/home/work/=/product_id/RJ01.html/?utm_medium=affiliate&utm_campaign=sns_link&utm_source=aff1&gclid=x",
            "https://www.dlsite.com/home/work/=/product_id/RJ01.html/?utm_medium=affiliate&utm_campaign=sns_link&utm_source=aff1",
        ],
        [
            "https://www.dmm.co.jp/digital/?utm_medium=dmm_affiliate&utm_source=aff-001&dmmref=top",
            "https://www.dmm.co.jp/digital/?utm_medium=dmm_affiliate&utm_source=aff-001",
        ],
        // 楽天の scid はアフィリエイト経由 (af_) のときだけ残す。
        [
            "https://item.rakuten.co.jp/shop/item/?scid=af_pc_etc&sc2id=af_101_0_0&l-id=top",
            "https://item.rakuten.co.jp/shop/item/?scid=af_pc_etc&sc2id=af_101_0_0",
        ],
        ["https://item.rakuten.co.jp/shop/item/?scid=wi_ich_top&l-id=top", "https://item.rakuten.co.jp/shop/item/"],
        [
            "https://www.temu.com/g.html?goods_id=1&_x_ads_channel=g&refer_share_id=a&_x_ns_sku_id=1",
            "https://www.temu.com/g.html?goods_id=1&refer_share_id=a",
        ],
        [
            "https://shop.example/p?id=1&irclickid=z&utm_source=x&aff_sub=1",
            "https://shop.example/p?id=1&irclickid=z&aff_sub=1",
        ],
        ["https://shop.example/lp?abm=z&rd_code=w&gclid=g", "https://shop.example/lp?abm=z&rd_code=w"],
        ["https://www.booking.com/hotel/jp/x.html?aid=123&label=blog", "https://www.booking.com/hotel/jp/x.html?aid=123&label=blog"],
        // Yahoo の sc_e はバリューコマース経由 (afvc) のときだけ残す。
        ["https://store.shopping.yahoo.co.jp/s/i.html?sc_e=afvc_shp_1&sc_i=x", "https://store.shopping.yahoo.co.jp/s/i.html?sc_e=afvc_shp_1"],
        ["https://store.shopping.yahoo.co.jp/s/i.html?sc_e=slga_pla", "https://store.shopping.yahoo.co.jp/s/i.html"],
    ];
    for (const [raw, want] of cases) {
        assert.equal(stripParams(new URL(raw), options).toString(), want, raw);
    }
});

test("stripParams はトラッキングを残してアフィリエイトだけを除去できる", () => {
    const options = { tracking: false, affiliate: true };
    const cases = [
        ["https://www.amazon.co.jp/dp/B0000/ref=sr_1_1?tag=aff-22&psc=1", "https://www.amazon.co.jp/dp/B0000/ref=sr_1_1?psc=1"],
        ["https://www.dlsite.com/w/?utm_medium=affiliate&utm_source=aff1", "https://www.dlsite.com/w/"],
        ["https://news.example/a?utm_source=news&a8=x", "https://news.example/a?utm_source=news"],
    ];
    for (const [raw, want] of cases) {
        assert.equal(stripParams(new URL(raw), options).toString(), want, raw);
    }
});

test("stripParams は対象サイトで機能に不要なパラメータをすべて除去する", () => {
    const cases = [
        [
            "https://www.amazon.co.jp/s?k=foo&i=aps&crid=x&sprefix=y&unknown_x=1&s=price-asc-rank",
            "https://www.amazon.co.jp/s?k=foo&i=aps&s=price-asc-rank",
        ],
        ["https://www.amazon.co.jp/dp/B0000?smid=A1&foo=bar&tag=x-22", "https://www.amazon.co.jp/dp/B0000?smid=A1"],
        [
            "https://www.amazon.co.jp/gp/aws/cart/add.html?ASIN.1=B0000&Quantity.1=1&foo=1",
            "https://www.amazon.co.jp/gp/aws/cart/add.html?ASIN.1=B0000&Quantity.1=1",
        ],
        // ログインなどパラメータが必須のページは対象外。
        [
            "https://www.amazon.co.jp/ap/signin?openid.return_to=https%3A%2F%2Fwww.amazon.co.jp%2F&foo=1",
            "https://www.amazon.co.jp/ap/signin?openid.return_to=https%3A%2F%2Fwww.amazon.co.jp%2F&foo=1",
        ],
        [
            "https://item.rakuten.co.jp/shop/item/?variantId=r-sku1&gad_source=1&xyz=1",
            "https://item.rakuten.co.jp/shop/item/?variantId=r-sku1",
        ],
        [
            "https://search.rakuten.co.jp/search/mall/foo/?p=2&s=2&unknown=1",
            "https://search.rakuten.co.jp/search/mall/foo/?p=2&s=2",
        ],
        ["https://www.temu.com/g.html?goods_id=1&sku_id=2&thumb_url=x&pic_w=1", "https://www.temu.com/g.html?goods_id=1&sku_id=2"],
        [
            "https://www.dlsite.com/maniax/fsr/=/?keyword=a&work_type%5B0%5D=SOU&unknown=1",
            "https://www.dlsite.com/maniax/fsr/=/?keyword=a&work_type%5B0%5D=SOU",
        ],
        ["https://www.dmm.co.jp/search/?searchstr=a&foo=1", "https://www.dmm.co.jp/search/?searchstr=a"],
        // 年齢確認は戻り先 (rurl) が必須。
        [
            "https://www.dmm.co.jp/age_check/=/?rurl=https%3A%2F%2Fwww.dmm.co.jp%2F&foo=1",
            "https://www.dmm.co.jp/age_check/=/?rurl=https%3A%2F%2Fwww.dmm.co.jp%2F&foo=1",
        ],
        // 対象外のサイトでは未知のパラメータを残す。
        ["https://shop.example/p?foo=1&id=2", "https://shop.example/p?foo=1&id=2"],
    ];
    for (const [raw, want] of cases) {
        assert.equal(stripParams(new URL(raw)).toString(), want, raw);
    }
});

test("stripParams は機能に不要なパラメータを除去してもアフィリエイトを残せる", () => {
    const options = { tracking: true, affiliate: false };
    assert.equal(
        stripParams(new URL("https://www.amazon.co.jp/dp/B0000?foo=bar&tag=x-22&linkCode=ogi"), options).toString(),
        "https://www.amazon.co.jp/dp/B0000?tag=x-22&linkCode=ogi",
    );
    // トラッキングの除去を無効にすると未知のパラメータも残る。
    assert.equal(
        stripParams(new URL("https://www.amazon.co.jp/dp/B0000?foo=bar&tag=x-22"), { tracking: false, affiliate: true }).toString(),
        "https://www.amazon.co.jp/dp/B0000?foo=bar",
    );
});

test("stripParams は AD EBiS の計測パラメータを dmai と一緒のときだけ除去する", () => {
    const cases = [
        // 楽天アフィリエイト経由の広告主 LP で実際に付いていた形。
        [
            "https://lp.example/lpa08/?code=AG035050&utm_source=rakutengroup&utm_medium=affiliate&argument=xRQPviEd&dmai=a69435dee4a58a",
            "https://lp.example/lpa08/?code=AG035050",
        ],
        // argument 単体はほかのサイトの機能パラメータかもしれないので残す。
        ["https://app.example/run?argument=1", "https://app.example/run?argument=1"],
    ];
    for (const [raw, want] of cases) {
        assert.equal(stripParams(new URL(raw)).toString(), want, raw);
    }
    assert.equal(
        stripParams(new URL(cases[0][0]), { tracking: true, affiliate: false }).toString(),
        "https://lp.example/lpa08/?code=AG035050&utm_source=rakutengroup&utm_medium=affiliate",
    );
});

test("stripParams は両方を無効にすると URL を変えない", () => {
    const raw = "https://www.amazon.co.jp/dp/B0000/ref=sr_1_1?tag=aff-22&utm_source=x";
    assert.equal(stripParams(new URL(raw), { tracking: false, affiliate: false }).toString(), raw);
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
        if (route.refresh) {
            return new Response(null, { status: 200, headers: { Refresh: route.refresh } });
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
    assert.equal(stripParams(result.final).toString(), "https://example.com/final?id=1");
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
    assert.equal(stripParams(result.final).toString(), "https://example.com/item?id=1");
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
        const csp = response.headers.get("Content-Security-Policy");
        assert.match(csp, /script-src 'self';/, path);
        // 認証プロキシの内側でもページが動くよう、リダイレクト先が検査される
        // ディレクティブはログイン画面を許可する。
        for (const directive of ["style-src", "manifest-src", "connect-src", "form-action"]) {
            assert.ok(
                csp.includes(`${directive} 'self' https://*.cloudflareaccess.com`),
                `${path}: ${directive} does not allow the Access login screen`,
            );
        }
        assert.doesNotMatch(csp, /unsafe-(inline|eval)/, path);
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

    const keep = await get(
        "https://redirector.example/api/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc&strip_tracking=0",
    );
    assert.equal((await keep.json()).destination, "https://example.com/final?id=1&utm_source=a8");

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

test("/-/resolve は除去オプションを受け付ける", async (t) => {
    t.after(stubUpstream());

    const response = await get(
        "https://redirector.example/-/resolve?u=https%3A%2F%2Fpx.a8.net%2Fsvt%2Fejp%3Fa8mat%3Dabc&strip_tracking=0",
    );
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("Location"), "https://example.com/final?id=1&utm_source=a8");
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
        // 属性値は HTML としてエスケープされているため復号する (DLsite など)。
        [
            `<meta http-equiv="refresh" content="0;URL=https://example.com/w?a=1&amp;b=2&#38;c=3&#x26;d=4">`,
            "https://example.com/w?a=1&b=2&c=3&d=4",
        ],
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
    assert.equal(stripParams(result.final).toString(), "https://example.com/download");
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

test("scriptRedirectTarget は中身のないページの JS 遷移だけを拾う", () => {
    const cases = [
        [`<html><head><script>location.href = "https://example.com/a";</script></head><body></body></html>`, "https://example.com/a"],
        [`<script>window.location.replace('https:\\/\\/example.com\\/b?x=1\\u0026y=2')</script>`, "https://example.com/b?x=1&y=2"],
        [`<script>setTimeout(function () { top.location = "/c"; }, 0);</script><p>Redirecting...</p>`, "/c"],
        [`<script type="text/javascript">document.location.assign("https://example.com/d")</script>`, "https://example.com/d"],
        [`<script>window.location.href="https://example.com/e"</script>`, "https://example.com/e"],
        // 本文のあるページは通常のページとみなし、スクリプトを根拠にしない。
        [`<p>${"本文".repeat(300)}</p><script>location.href = "https://example.com/f";</script>`, ""],
        // 比較や変数代入では宛先を確定できない。
        [`<script>if (location.href == "https://example.com/g") {}</script>`, ""],
        [`<script>location.href = next;</script>`, ""],
        // script 要素の外 (イベントハンドラ) は対象外。
        [`<a onclick="location.href='https://example.com/h'">go</a>`, ""],
        [`<script src="/app.js"></script>`, ""],
        ["", ""],
    ];
    for (const [html, want] of cases) {
        assert.equal(scriptRedirectTarget(html), want, html.slice(0, 60));
    }
});

test("resolveDestination は空の 200 応答の Refresh ヘッダを追跡する", async (t) => {
    const restore = stubFetch({
        "/click": { refresh: "0; url=https://example.com/landing?utm_source=mail" },
        "/landing": { status: 200 },
    });
    t.after(restore);

    const result = await resolveDestination(new URL("https://tracker.example/click"), new Map());
    assert.equal(stripParams(result.final).toString(), "https://example.com/landing");
    assert.deepEqual(hopLabels(result.hops), ["https://example.com/landing"]);
});

test("resolveDestination は JS で即座に遷移するページを追跡する", async (t) => {
    const restore = stubFetch({
        "/click": { html: `<html><body><script>window.location.replace("https://example.com/js?id=1&gclid=x");</script></body></html>` },
        "/js": { status: 200 },
    });
    t.after(restore);

    const result = await resolveDestination(new URL("https://tracker.example/click"), new Map());
    assert.equal(stripParams(result.final).toString(), "https://example.com/js?id=1");
    assert.equal(result.hops.length, 1);
});

test("resolveDestination は JS 遷移の危険な宛先を拒否する", async (t) => {
    const restore = stubFetch({
        "/click": { html: `<script>location.href = "http://127.0.0.1/admin";</script>` },
    });
    t.after(restore);

    await assert.rejects(() => resolveDestination(new URL("https://tracker.example/click"), new Map()), {
        status: 403,
    });
});

test("resolveDestination は自分自身への refresh を最終地点として扱う", async (t) => {
    const restore = stubFetch({
        "/news": { html: `<meta http-equiv="refresh" content="300;url=https://example.com/news">` },
    });
    t.after(restore);

    const result = await resolveDestination(new URL("https://example.com/news"), new Map());
    assert.equal(result.final.toString(), "https://example.com/news");
    assert.equal(result.hops.length, 0);
});

test("resolveDestination は本文を上限までしか読まない", async (t) => {
    const original = globalThis.fetch;
    let pulled = 0;
    globalThis.fetch = async () => {
        const chunk = new TextEncoder().encode("a".repeat(16 * 1024));
        const body = new ReadableStream({
            pull(controller) {
                pulled++;
                controller.enqueue(chunk);
            },
        });
        return new Response(body, { status: 200, headers: { "Content-Type": "text/html" } });
    };
    t.after(() => {
        globalThis.fetch = original;
    });

    const result = await resolveDestination(new URL("https://example.com/huge"), new Map());
    assert.equal(result.hops.length, 0);
    assert.ok(pulled < 10, `read ${pulled} chunks`);
});

test("認証プロキシのセッション切れを検出できる", async () => {
    const script = await readFile(new URL("../shared/ui/app.js", import.meta.url), "utf8");

    // リダイレクトを追うと別オリジンへの要求になり CORS で失敗するため、
    // 追わずに不透明な応答として受け取る必要がある。
    assert.match(script, /redirect: "manual"/);
    assert.match(script, /opaqueredirect/);
});
