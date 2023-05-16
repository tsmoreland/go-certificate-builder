//
// Copyright © 2023 Terry Moreland
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

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
