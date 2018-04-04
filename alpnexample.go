package main

import (
	"bufio"
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
	"os"
	"strings"
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
	Cert    tls.Certificate
	KeyAuth string
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

	shasum := sha256.Sum256([]byte(cs.KeyAuth))
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

func runServer() *CertSelection {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("tls.LoadX509KeyPair(): %v", err)
	}

	cs := &CertSelection{
		Cert:    cert,
		KeyAuth: "aaaaaaaaaaaaaa",
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

	go func() {
		log.Println("Running :80 -> :443 redirect")
		if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
			log.Fatalf("ListenAndServe :80 error: %v", err)
		}
	}()

	go func() {
		log.Println("Running TLS server")
		if err := s.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("ListenAndServeTLS error: %v", err)
		}
	}()

	return cs
}

func redirectTLS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}

func closeHandle(_ *http.Server, conn *tls.Conn, _ http.Handler) {
	log.Println("Closing connection.")
	conn.Close()
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	log.Printf("Running server for %v", domain)
	cs := runServer()
	for {
		fmt.Println("Provide keyAuth to set up challenge:")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		fmt.Printf("Setting keyAuth to --> %s <--\n", text)
		cs.KeyAuth = text
	}
}
