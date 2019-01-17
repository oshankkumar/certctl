package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"time"
)

// CertTemplate creates a cert template
// To create a new certificate, we first have to provide a template for one.
func CertTemplate(isCA bool, ipAddrs []net.IP) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Org.Inc"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // valid for an year
		IsCA:                  isCA,
		IPAddresses:           ipAddrs,
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

// Certificates must be signed by the private key of a parent certificate.
// Of course, there always has to be a certificate without a parent,
// and in these cases the certificate’s private key must be used in lieu of a parent’s.
//
// x509.CreateCertificate takes 4 arguments (plus a source of randomness).
// The template of the certificate we want to create, the public key we want to wrap,
// the parent certificate, and the parent’s private key.
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}, w io.Writer) (cert *x509.Certificate, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return
}

// CreateRSAKeyPair generates an RSA keypair of the given bit size using the
// random source random (for example, crypto/rand.Reader) and write its pem
// encoding to writer w
func CreateRSAKeyPair(random io.Reader, bits int, w io.Writer) (priv *rsa.PrivateKey, err error) {
	priv, err = rsa.GenerateKey(random, bits)
	if err != nil {
		return
	}

	err = pem.Encode(w, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return
}
