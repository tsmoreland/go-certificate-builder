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
	ExportFormatPemPublicKey ExportFormat = iota
	ExportFormatPemPrivateKey
	ExportFormatPFX
)

func WriteFile(filename string, encoding ExportFormat, certificate *x509.Certificate, key *rsa.PrivateKey, password string) error {
	switch encoding {
	case ExportFormatPemPublicKey:
		return writePublicPemFile(filename, certificate)
	case ExportFormatPemPrivateKey:
		return writePrivatePemFile(filename, key)
	case ExportFormatPFX:
		return writePfxFile(filename, certificate, key, password)
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

func writePfxFile(filename string, cert *x509.Certificate, key *rsa.PrivateKey, password string) error {
	pfxBytes, err := pkcs12.Encode(rand.Reader, key, cert, []*x509.Certificate{}, password)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, pfxBytes, 0644)
}
