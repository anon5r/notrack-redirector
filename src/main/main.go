package main

import (
	"io"
	"net/http"
	"strings"
	"log"
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

	// Start port as 9000
	http.ListenAndServe(":9000", mux)
}

// redirector
func redirector(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/favicon.ico" {
		return
	}

	// No query
	if r.URL.Query() != nil {
		queries := r.URL.Query()
		log.Printf("Request: ", r.Host, r.URL.Path, queries.Encode())

		// Specified domains
		if specParam, ok := specURL[r.Host]; ok {
			if len(specParam) > 1 {
				r.URL.Query()
				log.Printf("param = %+v", specParam)
				redirect := r.URL.Query().Get(specParam)
				log.Printf("value = %+v", redirect)
				if (len(redirect) > 5 && strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://")) {	
					log.Printf("redirect => ", redirect)
					w.Header().Set("Location", redirect)
					w.WriteHeader(http.StatusFound)
					return
				}
			}
		}

		// Common
		for _, key := range commonParams {
			if param, ok := queries[key]; ok {
				log.Printf("param = %+v", param)
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
