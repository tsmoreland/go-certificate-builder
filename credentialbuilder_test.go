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
	"crypto/x509"
	"fmt"
	"os"
	"software.sslmate.com/src/go-pkcs12"
	"testing"
)

func TestNewCertificateBuilder_ShouldReturnCertificateWithBitSize4096(t *testing.T) {
	cb := NewCertificateBuilder()
	if cb.bitSize != 4096 {
		t.Fatalf("bit size %v not equal to expected 4096", cb.bitSize)
	}
}

func TestCertificateBuilder_WithBitSize_ShouldUpdateBitSize_WhenGreaterThanOrEqualTo2048(t *testing.T) {
	cb := NewCertificateBuilder()
	cb.WithBitSize(2048)
	if cb.bitSize != 2048 {
		t.Fatalf("bit size %v not equal to expected 2048", cb.bitSize)
	}
}
func TestCertificateBuilder_WithBitSize_ShouldSetError_WhenLessThan2048(t *testing.T) {
	cb := NewCertificateBuilder()
	cb.WithBitSize(2047)
	if cb.err == nil {
		t.Fatal("error was not set when invalid bit size used")
	}
}

func TestCertificateBuilder_WithBitSize_ShouldNotUpdateValue_WhenErrIsSet(t *testing.T) {
	cb := NewCertificateBuilder()
	cb.err = fmt.Errorf("error")
	cb.WithBitSize(2048)

	if cb.bitSize == 2048 {
		t.Fatal("bit size was updated despite error being set")
	}

}

func TestCertificateBuilder_BuildSelfSignedCertificate_ShouldCreateCertForLocalApi_WhenConfigureIsValid(t *testing.T) {
	c, key, err := NewCertificateBuilder().
		WithDnsNames("localhost").
		WithCommonName("localhost").
		WithOrganization("Acme.").
		WithOrganizationUnit("Anvils").
		WithCity("Saskatoon").
		WithState("Saskatchewan").
		WithCountry("Canada").
		WithKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageDataEncipherment|x509.KeyUsageContentCommitment).
		WithEnhancedKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth).
		WithBasicConstraint().
		WithSubjectKeyIdentifierCritical(true).
		BuildSelfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}

	if err := WriteFile("go-server.pfx", ExportFormatPFX, c, key, pkcs12.DefaultPassword); err != nil {
		t.Fatal(err)
	}

	if _, err = os.Stat("go-server.pfx"); err != nil && os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err = os.Remove("go-server.pfx"); err != nil {
		t.Fatal(err)
	}

}
