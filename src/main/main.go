package main

import (
	"io"
	"net/http"
	"strings"
)

var specURL = map[string]string{
	"localhost:9000":       "a8ejpredirect",
	"px.a8.net":            "a8ejpredirect",
	"hb.afl.rakuten.co.jp": "pc",
}

var commonParams = []string{
	"url", "redirect", "jump",
}

func main() {

	mux := http.NewServeMux()

	// 「/」に対して処理を追加
	mux.HandleFunc("/", redirector)

	// 8080ポートで起動
	http.ListenAndServe(":9000", mux)
}

// redirector
func redirector(w http.ResponseWriter, r *http.Request) {

	// No query
	if r.URL.Query() != nil {
		// Specified domains
		if specParam, ok := specURL[r.Host]; ok {
			if len(specParam) > 6 && (strings.HasPrefix(specParam, "http://") || strings.HasPrefix(specParam, "https://")) {
				redirect := r.URL.Query().Get(specParam)
				w.Header().Set("Location", redirect)
				w.WriteHeader(http.StatusFound)
				return
			}
		}

		// Common
		queries := r.URL.Query()
		for _, key := range commonParams {
			if param, ok := queries[key]; ok {
				// log.Printf("param = %+v", param)
				// log.Printf("param.last! = %+v", param[len(param)-1])
				redirect := param[len(param)-1]
				w.Header().Set("Location", redirect)
				w.WriteHeader(http.StatusFound)
				return
			}
		}
	}
	io.WriteString(w, "Hello, "+r.URL.Path)
}
