package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

const (
	domain       = "boulder-dev-pub.maciejd.certsbridge.com"
	AcmeTlsProto = "acme-tls/1"
)

// As defined in https://rolandshoemaker.github.io/acme-tls-alpn/draft-ietf-acme-tls-alpn.html#tls-with-application-level-protocol-negotiation-tls-alpn-challenge
// id-pe OID + 30 (acmeIdentifier) + 1 (v1)
var IdPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}

type CertSelection struct {
	Cert  tls.Certificate
	Token string
}

func (cs *CertSelection) GetCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	log.Printf("GetCertificate(%v)", []string(ch.SupportedProtos))
	if len(ch.SupportedProtos) == 1 && ch.SupportedProtos[0] == AcmeTlsProto {
		log.Println("Serving ACME cert")
		cert, err := cs.GenerateACMECert()
		if err != nil {
			return nil, fmt.Errorf("GenerateACMECert(): %v", err)
		}
		return cert, nil
	}
	log.Println("Serving real cert")
	return &cs.Cert, nil
}

func (cs *CertSelection) GenerateACMECert() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey(): %v", err)
	}

	keyAuth := cs.Token // TODO: build real key authorization from token.
	shasum := sha256.Sum256([]byte(keyAuth))
	acmeExtension := pkix.Extension{
		Id:       IdPeAcmeIdentifierV1,
		Critical: true,
		Value:    shasum[:],
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Invalid Org."},
		},
		Issuer:                pkix.Name{Organization: []string{"Invalid Org."}},
		DNSNames:              []string{domain},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotBefore:             time.Now().Add(-1 * time.Second),
		NotAfter:              time.Now().Add(1 * time.Hour),
		SerialNumber:          big.NewInt(1),
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{acmeExtension},
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate(): %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  key,
	}, nil
}

func runServer() error {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return fmt.Errorf("tls.LoadX509KeyPair(): %v", err)
	}

	cs := &CertSelection{
		Cert:  cert,
		Token: "aaaaaaaaaaaaaa",
	}

	config := &tls.Config{
		GetCertificate: cs.GetCertificate,
		ServerName:     domain,
		NextProtos: []string{
			"http/1.1",
			AcmeTlsProto,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("handling /")
		w.Write([]byte("ACME tls-alpn example. Hello, world!"))
	})

	s := &http.Server{
		Addr:      ":443",
		TLSConfig: config,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
			AcmeTlsProto: closeHandle,
		},
	}
	return s.ListenAndServeTLS("", "")
}

func closeHandle(_ *http.Server, conn *tls.Conn, _ http.Handler) {
	log.Println("Closing connection.")
	conn.Close()
}

func main() {
	log.Printf("Running server for %v", domain)
	err := runServer()
	if err != nil {
		log.Fatal(err)
	}
}
