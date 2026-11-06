/**
 * Anti-Tracking URL Redirector のルール定義。
 * Cloudflare Worker 実装 (src/cloudflare-worker/worker.js) が読み込む。
 *
 * パラメータ除去ルールの出典は、特に断りがなければ次の 2 つ。
 *   - ClearURLs: https://rules2.clearurls.xyz/data.minify.json
 *   - AdGuard URL Tracking filter:
 *     https://github.com/AdguardTeam/AdguardFilters/tree/master/TrackParamFilter
 *
 * 正規表現は文字列で記述し、worker.js 側でコンパイルする。
 */

/** Amazon のマーケットプレイス。 */
const AMAZON = [
    "amazon.com", "amazon.co.jp", "amazon.co.uk", "amazon.de", "amazon.fr",
    "amazon.it", "amazon.es", "amazon.nl", "amazon.se", "amazon.pl",
    "amazon.com.be", "amazon.com.tr", "amazon.ca", "amazon.com.mx", "amazon.com.br",
    "amazon.com.au", "amazon.in", "amazon.sg", "amazon.ae", "amazon.sa", "amazon.eg",
];

const ALIEXPRESS = ["aliexpress.com", "aliexpress.us", "aliexpress.ru"];

const EBAY = [
    "ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr", "ebay.it", "ebay.es",
    "ebay.ca", "ebay.com.au", "ebay.at", "ebay.ch", "ebay.ie", "ebay.nl", "ebay.pl",
];

export default {
    /**
     * 上流として接続を許可するトラッキングサービス。302 を返す経路はここに
     * 限定される。
     *
     * 誰でも任意の URL を登録できる短縮 URL サービス (t.co, bit.ly など) を
     * 追加してはならない。追加するとオープンリダイレクタ化する。
     * paths が空なら当該ホストの全パスを許可する。
     */
    trackers: [
        { host: "px.a8.net", paths: ["^/svt/"] },
        { host: "hb.afl.rakuten.co.jp", paths: ["^/ichiba/[\\w.\\-]+", "^/hgc/[\\w.\\-]+", "^/hsc/[\\w.\\-]+"] },
        { host: "ck.jp.ap.valuecommerce.com", paths: ["^/servlet/referral"] },
        { host: "af.moshimo.com", paths: ["^/af/c/click"] },
        { host: "t.afi-b.com", paths: [] },
        { host: "click.linksynergy.com", paths: [] },
    ],

    /*
     * 最終 URL から除去するパラメータ。tracking (計測用) と affiliate
     * (アフィリエイト / 紹介報酬用) に分け、利用者がそれぞれの除去を選べる
     * ようにする。1 つのパラメータが両方に当てはまる場合は affiliate として
     * 扱う。
     *
     *   names     完全一致 (大文字小文字を区別しない。小文字で記述する)
     *   prefixes  前方一致 (同上)
     *   hosts     ホストを限定したルール。suffixes はサフィックス一致。
     *             pathPatterns はパスから取り除く部分の正規表現。
     *
     * ref / pid / sid / cid のように正規の機能パラメータと衝突しうる名前は
     * names には入れず、hosts でホストを限定して扱う。
     */
    tracking: {
        prefixes: [
            "utm_", "mtm_", "pk_", "piwik_", "matomo_", "hsa_", "vero_", "oly_",
            "trk_", "_bta_", "__hs", "ito_", "at_custom", "spm_",
        ],
        names: [
            "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
            "fbclid", "msclkid", "yclid", "twclid", "ttclid",
            "igshid", "igsh", "li_fat_id", "rdt_cid", "epik",
            "s_kwcid", "ef_id", "mkt_tok", "wickedid", "_openstat",
            "yadcid", "yadid", "_ga", "_gl", "__s",
            "mc_cid", "mc_eid", "ml_subscriber", "ml_subscriber_hash",
            "fb_action_ids", "fb_action_types", "fb_source", "fb_ref",
            "action_object_map", "action_type_map", "action_ref_map",
            "msockid",
        ],
        hosts: [
            {
                suffixes: AMAZON,
                names: [
                    "ref", "ref_", "psc", "qid", "sr", "sprefix", "crid", "dib", "dib_tag",
                    "content-id", "_encoding", "th", "refrid", "dchild", "spia", "aaxitk",
                    // Google 広告経由の流入計測。
                    "hvadid", "hvbmt", "hvdev", "hvlocphy", "hvnetw", "hvqmt", "hvrand",
                    "hvtargid", "hydadcr", "adgrpid",
                    "social_share", "starsleft", "skiptwisterog",
                ],
                prefixes: ["pd_rd_", "pf_rd_"],
                // /dp/B000/ref=sr_1_1 のようにパスにも計測情報を埋め込む。
                pathPatterns: ["/ref=[^/]*"],
            },
            {
                suffixes: ["rakuten.co.jp"],
                // scid / sc2id はアフィリエイト経由 (af_) なら markers で affiliate 扱いになる。
                names: ["scid", "sc2id", "iasid", "l-id", "l2-id", "s-id", "trflg", "bk"],
            },
            {
                suffixes: ["temu.com"],
                // goods_id / sku_id は商品と仕様の指定なので残す。
                names: [
                    "_x_ads_account", "_x_ads_creative_id", "_x_ads_id", "_x_ads_set",
                    "_x_ads_channel", "_x_ads_sub_channel", "_x_bg_adid", "_x_from",
                    "_x_vst_scene", "_x_campaign", "_x_cid", "_x_sessn_id",
                    "_x_channel_scene", "_x_channel_src", "adg_ctx", "mrk_rec",
                    "_p_jump_id", "_p_rfs", "_bg_fs", "refer_page_el_sn", "refer_page_sn",
                    "refer_page_name", "refer_page_id", "refer_source", "top_gallery_url",
                    "spec_gallery_id", "freesia_scene", "share_img", "from_share",
                ],
                prefixes: ["_x_ns_", "_oak_"],
            },
            { suffixes: ["dmm.co.jp", "dmm.com"], names: ["dmmref", "i3_ref", "i3_ord"] },
            {
                suffixes: ALIEXPRESS,
                names: [
                    "algo_pvid", "algo_expid", "algo_exp_id", "curpageloguid", "pdp_npi",
                    "spm", "scm", "scm_id", "scm-url", "utparam", "utparam-url", "pvid",
                    "gps-id", "ws_ab_test", "btsid",
                ],
            },
            {
                suffixes: EBAY,
                names: ["_trkparms", "_trksid", "_from", "amdata", "itmmeta", "itmprp", "ssspo", "sssrc", "ssuid"],
            },
            // mt (メディア種別) は表示に必要なので残す。
            { suffixes: ["apple.com"], names: ["itscg", "itsct", "ct", "pt"] },
            // sc_e はバリューコマース経由 (afvc) なら markers で affiliate 扱いになる。
            { suffixes: ["yahoo.co.jp"], names: ["sc_e", "sc_i", "mcr", "ei", "ark", "tpkgd"] },
            { suffixes: ["youtube.com"], names: ["si", "feature", "kw"] },
            { suffixes: ["youtu.be"], names: ["si", "feature"] },
            { suffixes: ["x.com", "twitter.com"], names: ["s", "t", "ref_src", "ref_url"] },
        ],

        /*
         * 残すパラメータを列挙するサイト。ここに挙げたホストでは、names /
         * prefixes に当てはまらないパラメータをすべて計測用として除去する。
         * 遷移先の表示や機能に不要なものは計測かアフィリエイトとみなす方針。
         *
         *   names / prefixes  残すパラメータ (小文字)。名前末尾の配列添字
         *                     (work_type[0] など) は比較前に取り除く。
         *   exceptPaths       対象外にするパスの正規表現。ログインや購入手続き
         *                     のようにパラメータが必須のページを除く。
         *
         * アフィリエイトの判定が先に行われるため、アフィリエイトを残す指定なら
         * ここで残さないものでも tag などは残る。
         */
        keepOnly: [
            {
                suffixes: AMAZON,
                names: [
                    // 検索結果・カテゴリ
                    "k", "i", "rh", "s", "page", "bbn", "node", "emi", "pct-off",
                    "low-price", "high-price", "field-keywords", "field-author",
                    "field-isbn", "field-publisher", "field-title", "url",
                    // 商品詳細 (出品者の指定、全出品者一覧の展開)
                    "smid", "m", "aod", "condition",
                    // 出品者ストア
                    "me", "seller", "marketplaceid",
                    // レビュー一覧
                    "filterbystar", "sortby", "pagenumber", "reviewertype", "formattype",
                    "mediatype", "filterbykeyword", "filterbylanguage",
                    // ほしい物リスト
                    "filter", "sort", "viewtype", "lek",
                    // 全ページ共通
                    "language", "currency", "ie",
                ],
                // カート追加リンク (ASIN.1=...&Quantity.1=...)
                prefixes: ["asin.", "quantity.", "offerlistingid."],
                exceptPaths: [
                    "^/ap/", "^/gp/buy/", "^/gp/cart/", "^/cart/", "^/checkout/",
                    "^/gp/css/", "^/gp/your-account/", "^/your-account/",
                ],
            },
            {
                suffixes: [
                    "item.rakuten.co.jp", "search.rakuten.co.jp", "www.rakuten.co.jp",
                    "books.rakuten.co.jp", "review.rakuten.co.jp",
                ],
                names: [
                    // 商品詳細のバリエーション
                    "variantid",
                    // 検索結果・店舗内カテゴリ
                    "p", "s", "min", "max", "f", "filter", "nitem", "v", "sid", "st", "k",
                    // 楽天ブックスの検索
                    "sitem", "keyword", "g", "spv", "author", "isbn", "pname",
                ],
            },
            {
                suffixes: ["temu.com"],
                names: [
                    "goods_id", "sku_id", "search_key", "filter_items", "sort", "sort_type",
                    "page", "opt_id", "opt_type", "cat_id", "mall_id",
                    "bgt_order_type", "parent_order_sn",
                ],
                exceptPaths: ["^/login"],
            },
            {
                // dmm.com 配下には FX など別サービスもあるため、ホストを限定する。
                suffixes: ["www.dmm.co.jp", "www.dmm.com", "book.dmm.com", "book.dmm.co.jp", "video.dmm.co.jp"],
                names: [
                    "cid", "searchstr", "sort", "page", "limit", "view", "floor", "service",
                    "article", "id", "term", "type", "category", "genre", "publisher",
                    "author", "series", "sale", "keyword", "q",
                ],
                // 年齢確認は戻り先 (rurl) が必須。
                exceptPaths: ["^/age_check/", "^/my/"],
            },
            {
                suffixes: ["www.dlsite.com"],
                names: [
                    "locale", "translation", "product_id", "maker_id",
                    // 検索結果 (/fsr/=/)
                    "keyword", "keyword_creater", "work_type", "type", "work_category",
                    "sex_category", "age_category", "genre", "options", "options_not",
                    "language", "price_low", "price_high", "price_category", "rate_average",
                    "release_term", "order", "per_page", "page", "show_type", "is_tl", "from_fsr",
                    // ランキング・レビュー・お気に入り
                    "term", "sort", "sub", "date", "filter",
                ],
            },
        ],
    },

    affiliate: {
        // HasOffers / TUNE (aff_id, aff_sub*) や AliExpress (aff_fcid, aff_fsk ...) など。
        prefixes: ["aff_"],
        names: [
            // 許可リストの ASP が広告主の LP に付けるクリック識別子。
            "a8", // A8.net
            "vc_lpp", // ValueCommerce (ITP 対応の案内で「弊社が付与するパラメータ」と明記)
            "abm", // afb (afb のソケット通信導入資料に「URL に abm=... を付与」と明記)
            "rd_code", // もしもアフィリエイトのセッション方式 (広告主がリンク先に ?rd_code={{CODE}} を設定)
            "irclickid", "irgwc", // Impact
            "cjevent", // CJ
            "awc", // Awin
            "sscid", // ShareASale
            "ranmid", "raneaid", "ransiteid", // Rakuten Advertising (LinkShare)
            "admitad_uid", // Admitad
            "tduid", // Tradedoubler
            "utm_affiliate", // もしもアフィリエイト
            "x-clickref", // Partnerize
        ],
        hosts: [
            {
                suffixes: AMAZON,
                names: [
                    "tag", "linkcode", "linkid", "creative", "creativeasin", "ascsubtag", "camp",
                    "associatetag", "asc_campaign", "asc_refurl", "asc_source",
                ],
            },
            { suffixes: ["rakuten.co.jp"], names: ["rafcid"] },
            // 共有した利用者への紹介報酬。
            { suffixes: ["temu.com"], names: ["refer_share_id", "refer_share_suin", "refer_share_channel"] },
            { suffixes: ALIEXPRESS, names: ["sk", "dp", "af", "terminal_id", "mall_affr"] },
            // eBay Partner Network。
            { suffixes: EBAY, names: ["campid", "mkcid", "mkrid", "mkevt", "toolid", "customid"] },
            // Apple Services Performance Partners の affiliate token。
            { suffixes: ["apple.com"], names: ["at"] },
            // aid はアフィリエイト ID、label はパートナーが付ける設置場所ごとのラベル
            // (Booking.com Affiliate Partner Support の "Links" より)。
            { suffixes: ["booking.com"], names: ["aid", "label"] },
        ],

        /*
         * パラメータの値からアフィリエイト経由と判断できる場合に、names /
         * prefixes を affiliate 扱いにする。param の値が pattern (正規表現、
         * 大文字小文字を区別しない) に一致したときに適用する。suffixes が
         * 空なら全ホストが対象。
         */
        markers: [
            // DMM (utm_medium=dmm_affiliate) と DLsite (utm_medium=affiliate) は
            // utm_source にアフィリエイト ID を入れる。実際のリダイレクトで確認。
            { suffixes: [], param: "utm_medium", pattern: "affiliate", prefixes: ["utm_"] },
            // 楽天アフィリエイト経由では scid=af_pc_etc&sc2id=af_101_0_0 のように付く。
            { suffixes: ["rakuten.co.jp"], param: "scid", pattern: "^af_", names: ["scid", "sc2id"] },
            // バリューコマース経由の Yahoo!ショッピングは sc_e=afvc_shp_<数字> が付く。
            { suffixes: ["yahoo.co.jp"], param: "sc_e", pattern: "^afvc", names: ["sc_e"] },
        ],
    },
};
