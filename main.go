package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	var backendUrl string
	var salt string
	var tls bool
	var addr, tlsAddr, keyFile, certFile string
	var err error
	flag.BoolVar(&tls, "tls", true, "serve TLS requests")
	flag.StringVar(&keyFile, "key", "/etc/ssl/private/key.pem", "private key")
	flag.StringVar(&certFile, "crt", "/etc/ssl/private/cert.pem", "certificate")
	flag.StringVar(&backendUrl, "b", "http://localhost:80", "backend to route requests to if autenticated")
	flag.StringVar(&salt, "s", "salt", "salt to generate links")
	flag.StringVar(&addr, "a", ":80", "ip address:port to listen for http requests")
	flag.StringVar(&tlsAddr, "sa", ":443", "ip address:port to listen for https requests")

	flag.Parse()

	backend, err := url.Parse(backendUrl)
	if err != nil {
		log.Println("Error parsing backend url: ", err)
		os.Exit(-1)
	}

	proxy := httputil.NewSingleHostReverseProxy(backend)
	http.HandleFunc("/", handler(proxy, salt))

	if tls {
		err = http.ListenAndServeTLS(tlsAddr, certFile, keyFile, nil)
	} else {
		err = http.ListenAndServe(addr, nil)
	}

	if err != nil {
		log.Println("Error starting the proxy server: ", err)
		os.Exit(-1)
	}
}

func checkLink(salt, digest, start, end, id string) bool {
	d := fmt.Sprintf("%x", hash([]byte(salt), []byte(start), []byte(end), []byte(id)))
	s, err := strconv.ParseInt(start, 10, 64)
	if err != nil {
		log.Println("Unable to parse starting time: ", err)
		return false
	}
	e, err := strconv.ParseInt(end, 10, 64)
	if err != nil {
		log.Println("Unable to parse ending time: ", err)
		return false
	}
	now := time.Now().Unix()
	if now < s || now > e {
		log.Println("Link expired: ", s, e, now)
		return false
	}
	log.Println(d)
	return d == digest
}

func handler(p *httputil.ReverseProxy, salt string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := base64.StdEncoding.DecodeString(r.URL.Path[1:])
		if err != nil {
			http.Error(w, "auth error", 401)
			log.Println("Unable to decode url. ", err, r.URL.Path[1:])
			return
		}
		q := strings.Split(string(token), "/")
		log.Println(len(q))
		if !checkLink(salt, q[0], q[1], q[2], q[3]) {
			http.Error(w, "auth error", 401)
			log.Println("Unable to authentify token. ", q)
			return
		}
		r.URL.Path = "/"
		p.ServeHTTP(w, r)
	}
}

func hash(data ...[]byte) []byte {
	hasher := sha256.New()

	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}

	return hasher.Sum(nil)[:]
}
