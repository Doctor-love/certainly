package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"net/http/httputil"
	"net/url"
	"io/ioutil"
	"log"
	"strings"
)

var serverAddress, serverCert, serverKey, clientCAFile, targetURL string

func init() {
	flag.StringVar(&serverAddress, "server-address", ":9090", "Listening address for proxy server")
	flag.StringVar(&serverCert, "server-cert", "", "Path to server certificate bundle in PEM format")
	flag.StringVar(&serverKey, "server-key", "", "Path to server certificate private key in PEM format")
	flag.StringVar(&clientCAFile, "client-ca", "", "Path to client CA in PEM format")
	flag.StringVar(&targetURL, "target-url", "", "Target URL for proxied requests")
	flag.Parse()

}

// stolen from NewSingleHostReverseProxy
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// stolen from NewSingleHostReverseProxy
func NewCertainlyReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		// this is probably unsafe ;)
		clientDN := req.TLS.PeerCertificates[len(req.TLS.PeerCertificates)-1].Subject.String()
		req.Header.Set("Certainly-Client-DN", clientDN)
	}
	return &httputil.ReverseProxy{Director: director}
}

func main() {
	clientCAData, err := ioutil.ReadFile(clientCAFile)
	if err != nil {
		log.Fatal(err)
	}

	clientCA := x509.NewCertPool()
	clientCA.AppendCertsFromPEM(clientCAData)

	targetURL, err := url.Parse(targetURL)
	if err != nil {
		log.Fatal(err)
	}

	serverTLSConfig := &tls.Config{
		ClientCAs: clientCA,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	proxyServer := http.Server{
		Addr: serverAddress,
		Handler: NewCertainlyReverseProxy(targetURL),
		TLSConfig: serverTLSConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Fatal(proxyServer.ListenAndServeTLS(serverCert, serverKey))
}
