package main

import (
    "io"
    "net/http"
    "strings"
    "log"
    "regexp"
)


var specPath = []map[string]string{
        // //px.a8.net/svt/ejp?a8mat=
        map[string]string{`/svt/ejp` :            "a8ejpredirect"},
        // //hb.afl.rakuten.co.jp/ichiba/123456abc.d78ef9ab.12345def.a6bc789d/...?pc=
        map[string]string{`/ichiba/[\w\._]+`:     "pc"},
        // //hb.afl.rakuten.co.jp/hgc/123456abc.d78ef9ab.12345def.a6bc789d/_RTtrbk-t123456?pc=
        map[string]string{`/hgc/[\w\._]+`:        "pc"},
        // //ck.jp.ap.valuecommerce.com/servlet/referral?sid=123456&pid=0123456789&vc_url=
        map[string]string{`/servlet/referral`:    "vc_url"},
}

var commonParams = []string{
    "url", "redirect", "jump",
}

func main() {

    mux := http.NewServeMux()

    // 「/」に対して処理を追加
    mux.HandleFunc("/", redirector)

    // Start port as 9000
    http.ListenAndServe(":9000", mux)
}

// redirector
func redirector(w http.ResponseWriter, r *http.Request) {

    urlParams := map[string][]string{}
    urlParams["px.a8.net"]                  = []string{"a8ejpredirect"}
    urlParams["hb.afl.rakuten.co.jp"]       = []string{"pc"}
    urlParams["ck.jp.ap.valuecommerce.com"] = []string{"vc_url"}

    if r.URL.Path == "/favicon.ico" {
        return
    }

    // No query
    if r.URL.Query() != nil {
        queries := r.URL.Query()
        log.Printf("Request: ", r.Host, r.URL.Path, queries.Encode())

        // Specified domains
        if param, ok := urlParams[r.Host]; ok {
            size := len(param)
            if size > 0 {
                for i := 0; i < size; i++ {
                    paramName := param[i]
                    r.URL.Query()
                    log.Printf("param = %+v", paramName)
                    redirect := r.URL.Query().Get(paramName)
                    actionRedirect(redirect, w, r)
                }
            }
        }
        for _, v := range  specPath {
            for pattern, param := range v {
                if regexp.MustCompile(`^`+pattern).MatchString(r.URL.Path) {
                    log.Printf("param = %+v", param)
					redirect := r.URL.Query().Get(param)
                    actionRedirect(redirect, w, r)
                }
            }
        }


        // Common
        for _, key := range commonParams {
            if param, ok := queries[key]; ok {
                log.Printf("param = %+v", param)
                // log.Printf("param.last! = %+v", param[len(param)-1])
                redirect := param[len(param)-1]
                actionRedirect(redirect, w, r)
                return
            }
        }
    }
    io.WriteString(w, "Hello, "+r.URL.Path)
}

func actionRedirect(redirect string, w http.ResponseWriter, r *http.Request) {
    if redirect != "" {
        log.Printf("value = %+v", redirect)
        if (len(redirect) > 5 && strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://")) {    
            log.Printf("redirect => ", redirect)
            w.Header().Set("Location", redirect)
            w.WriteHeader(http.StatusFound)
            return
        }
    }
}
