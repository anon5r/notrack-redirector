package main

import (
	"io"
	"net/http"
	"strings"
	"log"
)



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
    urlParams["localhost:9000"]       = []string{"a8ejpredirect","pc"}
    urlParams["px.a8.net"]            = []string{"a8ejpredirect"}
    urlParams["hb.afl.rakuten.co.jp"] = []string{"pc"}

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
