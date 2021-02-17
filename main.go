package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"io/ioutil"
	"strings"
	"errors"
	"bufio"
	"log"
	"os"
)

// Setup and parsing of command line arguments/globals
var serverAddress, serverCert, serverKey, clientCAFile, clientCRLFile, targetURL, trustedCNsFile string
var addHSTS, confFromEnv bool
var trustedCNs []string
var crl *pkix.CertificateList

// Check if certificate is revoked using provided CRL - inspired by cfssl/revoke/revoke.go
func isRevoked(cert *x509.Certificate) (revoked bool) {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true
		}
	}

	return false
}

// Loads CN whitelist from file
func loadCNWhitelist(trustedCNsFile string) (trustedCNs []string, err error) {
	if trustedCNsFile == "" {
		log.Print("WARN: No CN whitelist specified")
		return trustedCNs, err
	}

	log.Print("INFO: Loading CN whitelist from file: ", trustedCNsFile)

	trustedCNsData, err := os.Open(trustedCNsFile)
	if err != nil {
		return trustedCNs, err
	}

	trustedCNsScanner := bufio.NewScanner(trustedCNsData)

	for trustedCNsScanner.Scan() {
		entry := trustedCNsScanner.Text()

		// Ignore empty lines, seems like the resonsable thing to do
		if entry == "" {
			continue
		}

		trustedCNs = append(trustedCNs, entry)
	}

	if err := trustedCNsScanner.Err(); err != nil {
		return trustedCNs, err
	}

	trustedCNsData.Close()

	return trustedCNs, err
}

// Check if CN is included in white-list
func includedInWhitelist(cn string) (included bool) {
	log.Print("INFO: Checking if CN is included in whitelist: ", cn)

	for _, entry := range trustedCNs {
		if cn == entry {
			log.Print("INFO: CN is included in whitelist: ", cn)
			return true
		}
	}

	return false
}

// Perform additional validation of the verfified certificate chains
func validateCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (err error) {
	if len(trustedCNs) == 0 {
		return err
	}

	for _, verifiedChain := range verifiedChains {
		// Check if any certificate in the verified chain has been revoked
		for _, verifiedCert := range verifiedChain {
			if isRevoked(verifiedCert) {
				return errors.New(fmt.Sprint(
					"WARN: Peer provided revoked certificate: ",
					verifiedCert.SerialNumber))
			}
		}

		// If CN is whitelisted, we proceede with the request
		if includedInWhitelist(verifiedChain[0].Subject.CommonName) {
			return err
		}
	}

	return errors.New("WARN: Could not find a matching CN in whitelist")
}

// Based on httputil.singleJoiningSlash from standard library
func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")

	switch {
	case aSlash && bSlash:
		return a + b[1:]

	case !aSlash && !bSlash:
		return a + "/" + b
	}

	return a + b
}

// Based on httputil.NewSingleHostReverseProxy from standard library
func newReverseProxy(targetURL *url.URL, addHSTS bool) *httputil.ReverseProxy {

	// Modification of proxied requests sent to target URL
	reqModifier := func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.URL.Path = singleJoiningSlash(targetURL.Path, req.URL.Path)

		// Work-around for issue with port being included in "Host" header
		req.Host = targetURL.Hostname()

		// Handling of query parameters, if specified in target URL
		if targetURL.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetURL.RawQuery + req.URL.RawQuery

		} else {
			req.URL.RawQuery = targetURL.RawQuery + "&" + req.URL.RawQuery
		}

		// If no user agent is specified, don't use httplib's default
		if _, reqUA := req.Header["User-Agent"]; !reqUA {
			req.Header.Set("User-Agent", "")
		}

	}

	// Modification of proxied responses returned from target URL
	resModifier := func(res *http.Response) (err error) {
		if addHSTS == true {
			res.Header.Set("Strict-Transport-Security", "max-age=31536000")
		}

		// Check if any cookies are being set and add "Secure" attribute if needed
		if len(res.Cookies()) > 0 {
			var modifiedCookies []*http.Cookie

			for _, cookie := range res.Cookies() {
				cookie.Secure = true
				modifiedCookies = append(modifiedCookies, cookie)
			}

			res.Header.Del("Set-Cookie")

			for _, cookie := range modifiedCookies {
				res.Header.Add("Set-Cookie", cookie.String())
			}
		}

		return err
	}

	return &httputil.ReverseProxy{Director: reqModifier, ModifyResponse: resModifier}
}

func init() {
	flag.StringVar(&serverAddress, "server-address", ":9090", "Listening address for proxy server")
	flag.StringVar(&serverCert, "server-cert", "", "Path to server certificate bundle in PEM format")
	flag.StringVar(&serverKey, "server-key", "", "Path to server certificate private key in PEM format")
	flag.StringVar(&clientCAFile, "client-ca", "", "Path to client CA in PEM format")
	flag.StringVar(&clientCRLFile, "client-crl", "", "Path to client CRL file in PEM format")
	flag.StringVar(&targetURL, "target-url", "", "Target URL for proxied requests")
	flag.BoolVar(&addHSTS, "add-hsts", false, "Add Strict Transport Security (HSTS) header to responses")
	flag.StringVar(&trustedCNsFile, "cn-whitelist", "", "Path to new line separated file containg allowed CNs")
	flag.BoolVar(&confFromEnv, "env", false, "Read configuration from enviroment variables")
	flag.Parse()

	if confFromEnv == true {
		log.Print("INFO: Reading configuration from environment variables")

		serverAddress = os.Getenv("CERTAINLY_SERVER_ADDRESS")
		serverCert = os.Getenv("CERTAINLY_SERVER_CERT")
		serverKey = os.Getenv("CERTAINLY_SERVER_KEY")
		clientCAFile = os.Getenv("CERTAINLY_CLIENT_CA")
		clientCRLFile = os.Getenv("CERTAINLY_CLIENT_CRL")
		targetURL = os.Getenv("CERTAINLY_TARGET_URL")
		trustedCNsFile = os.Getenv("CERTAINLY_CN_WHITELIST")

		if os.Getenv("CERTAINLY_ADD_HSTS") == "true" {
			addHSTS = true
		}
	}
}

func main() {
	clientCAData, err := ioutil.ReadFile(clientCAFile)
	if err != nil {
		log.Fatal("ERROR: Failed to read CA data from file: ", err)
	}

	clientCA := x509.NewCertPool()
	clientCA.AppendCertsFromPEM(clientCAData)

	if clientCRLFile != "" {
		clientCRLData, err := ioutil.ReadFile(clientCRLFile)
		if err != nil {
			log.Fatal("ERROR: Failed to read CRL data from file: ", err)
		}

		crl, err = x509.ParseCRL(clientCRLData)
		if err != nil {
			log.Fatal("ERROR: Failed to parse CRL data: ", err)
		}
	}

	targetURL, err := url.Parse(targetURL)
	if err != nil {
		log.Fatal("ERROR: Failed to parse target URL: ", err)
	}

	trustedCNs, err = loadCNWhitelist(trustedCNsFile)
	if err != nil {
		log.Fatal("ERROR: Failed to load CN whitelist: ", err)
	}

	serverTLSConfig := &tls.Config{
		ClientCAs: clientCA,
		ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: validateCert,
		MinVersion: tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	proxy := newReverseProxy(targetURL, addHSTS)

	proxyServer := http.Server{
		Addr: serverAddress,
		Handler: proxy,
		TLSConfig: serverTLSConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Fatal(proxyServer.ListenAndServeTLS(serverCert, serverKey))
}
