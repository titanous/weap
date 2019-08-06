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
	listenAddr := flag.String("listen", ":1812", "UDP listen address")
	flag.Parse()

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
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
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
