package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/titanous/weap/eaptls"
	"github.com/titanous/weap/radius_eaptls"
	"layeh.com/radius"
)

func main() {
	certFile := flag.String("cert", "server.pem", "server TLS certificate chain file")
	keyFile := flag.String("key", "server-key.pem", "server TLS certificate key file")
	caFile := flag.String("ca", "ca.pem", "CA certificates file to trust for client auth")
	authKey := flag.String("authkey", "", "Message-Authenticator shared secret key")
	insecureTLS := flag.Bool("insecure-tls", false, "enable weak and broken TLS versions and ciphers")
	listenAddr := flag.String("listen", ":1812", "UDP listen address")
	flag.Parse()

	// enable TLS 1.3
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	l := log.New(os.Stdout, "", log.Lmicroseconds|log.Lshortfile)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		l.Fatal("error loading keypair:", err)
	}

	caData, err := ioutil.ReadFile(*caFile)
	if err != nil {
		l.Fatal("error reading CA file:", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	config := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		ClientCAs:              caPool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		SessionTicketsDisabled: true,                                     // resumed connections do not cache client certificate details
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256}, // enable only curves with constant-time ASM implementations on amd64
		MinVersion:             tls.VersionTLS12,                         // versions before TLS 1.2 have known weaknesses
		CipherSuites: []uint16{ // only allow forward-secret ciphers with no known weaknesses
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	if *insecureTLS {
		config.MinVersion = tls.VersionTLS10
		config.CipherSuites = append(config.CipherSuites,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_RC4_128_SHA,
		)
	}
	tlsServer, err := eaptls.NewServer(&eaptls.ServerConfig{
		TLSConfig: config,
		Logger:    l,
	})
	if err != nil {
		l.Fatal("error creating eaptls server:", err)
	}

	s := &radius.PacketServer{
		Addr:         *listenAddr,
		SecretSource: radius.StaticSecretSource([]byte(*authKey)),
		Handler:      radius_eaptls.NewHandler(tlsServer, l),
	}

	log.Fatal(s.ListenAndServe())
}
