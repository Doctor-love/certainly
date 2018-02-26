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

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	proxyServer := http.Server{
		Addr: serverAddress,
		Handler: proxy,
		TLSConfig: serverTLSConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Fatal(proxyServer.ListenAndServeTLS(serverCert, serverKey))
}
