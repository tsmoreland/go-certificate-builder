package x509certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"software.sslmate.com/src/go-pkcs12"
)

type ExportFormat int32

const (
	PemPublicKey ExportFormat = iota
	PemPrivateKey
	PFX
)

func WriteFile(filename string, encoding ExportFormat, certificate *x509.Certificate, key *rsa.PrivateKey) error {
	switch encoding {
	case PemPublicKey:
		return writePublicPemFile(filename, certificate)
	case PemPrivateKey:
		return writePrivatePemFile(filename, key)
	case PFX:
		return writePfxFile(filename, certificate, key)
	default:
		return fmt.Errorf("unsupported encoding")
	}
}

func writePublicPemFile(filename string, cert *x509.Certificate) error {
	return writePemFile(filename, "CERTIFICATE", cert.Raw)
}
func writePrivatePemFile(filename string, key *rsa.PrivateKey) error {
	rawData := x509.MarshalPKCS1PrivateKey(key)
	return writePemFile(filename, "RSA PRIVATE KEY", rawData)
}

func writePemFile(filename string, label string, rawData []byte) error {
	buffer := bytes.Buffer{}
	if err := pem.Encode(&buffer, &pem.Block{Type: label, Bytes: rawData}); err != nil {
		return err
	}
	return os.WriteFile(filename, buffer.Bytes(), 0644)
}

func writePfxFile(filename string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	pfxBytes, err := pkcs12.Encode(rand.Reader, key, cert, []*x509.Certificate{}, pkcs12.DefaultPassword)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, pfxBytes, 0644)
}
