//
// Copyright © 2022 Terry Moreland
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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type CertificateBuilder struct {
	err                           error
	bitSize                       int
	commonName                    string
	organization                  string
	organizationUnit              string
	city                          string
	state                         string
	country                       string
	dnsNames                      []string
	keyUsage                      x509.KeyUsage
	enhancedKeyUsages             []x509.ExtKeyUsage
	extensions                    []pkix.Extension
	notBefore                     *time.Time
	notAfter                      *time.Time
	serialNumber                  *big.Int
	includeBasicConstraint        bool
	includeSubjectKeyIdentifier   bool
	subjectKeyIdentifierCritical  bool
	includeAuthorityKeyIdentifier bool
	isCertificateAuthority        bool
}

// NewCertificateBuilder creates a new certificate builder which can be used to configure and then build x509
//
//	certificates
func NewCertificateBuilder() *CertificateBuilder {
	return &CertificateBuilder{
		err:               nil,
		bitSize:           4096,
		commonName:        "",
		organization:      "",
		organizationUnit:  "",
		city:              "",
		state:             "",
		country:           "",
		dnsNames:          make([]string, 0, 0),
		enhancedKeyUsages: make([]x509.ExtKeyUsage, 0, 0),
		keyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature |
			x509.KeyUsageDataEncipherment | x509.KeyUsageContentCommitment,
		notBefore:    nil,
		notAfter:     nil,
		serialNumber: nil,
	}
}

// GetError returns the current error if set, otherwise nil
func (c *CertificateBuilder) GetError() error {
	return c.err
}

func (c *CertificateBuilder) WithBitSize(value int) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	if value < 2048 {
		c.err = fmt.Errorf("bitsize cannot be less than 2048")
		return c
	}

	c.bitSize = value
	return c
}

func (c *CertificateBuilder) WithIsCertificateAuthority(value bool) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.isCertificateAuthority = value
	return c
}

func (c *CertificateBuilder) WithCommonName(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	if len(value) == 0 {
		c.err = fmt.Errorf("common name cannot be empty")
		return c
	}

	c.commonName = value
	return c
}

func (c *CertificateBuilder) WithOrganization(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.organization = value
	return c
}

func (c *CertificateBuilder) WithOrganizationUnit(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.organizationUnit = value
	return c
}

func (c *CertificateBuilder) WithCity(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.city = value
	return c
}

func (c *CertificateBuilder) WithState(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.state = value
	return c
}

func (c *CertificateBuilder) WithCountry(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.country = value
	return c
}

func (c *CertificateBuilder) WithDnsNames(values ...string) *CertificateBuilder {
	if c.err != nil {
		return c
	}

	c.dnsNames = append(c.dnsNames, values...)
	return c
}

func (c *CertificateBuilder) WithKeyUsage(usage x509.KeyUsage) *CertificateBuilder {
	if c.err != nil {
		return c
	}

	c.keyUsage = usage
	return c
}

func (c *CertificateBuilder) WithEnhancedKeyUsage(values ...x509.ExtKeyUsage) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.enhancedKeyUsages = append(c.enhancedKeyUsages, values...)
	return c
}

func (c *CertificateBuilder) WithExtensions(values ...pkix.Extension) *CertificateBuilder {
	if c.err != nil {
		return c
	}

	c.extensions = append(c.extensions, values...)
	return c
}

func (c *CertificateBuilder) WithNotBefore(value time.Time) *CertificateBuilder {
	if c.err != nil {
		return c
	}

	c.notBefore = &value
	return c
}

func (c *CertificateBuilder) WithNotAfter(value time.Time) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.notAfter = &value
	return c
}

func (c *CertificateBuilder) WithSerialNumber(value *big.Int) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.serialNumber = value
	return c
}

func (c *CertificateBuilder) WithBasicConstraint() *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.includeBasicConstraint = true
	return c
}

func (c *CertificateBuilder) WithIncludeSubjectKeyIdentifier() *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.includeSubjectKeyIdentifier = true
	return c
}

func (c *CertificateBuilder) WithSubjectKeyIdentifierCritical(value bool) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.subjectKeyIdentifierCritical = value
	return c
}

func (c *CertificateBuilder) WithIncludeAuthorityKeyIdentifier() *CertificateBuilder {
	if c.err != nil {
		return c
	}
	c.includeAuthorityKeyIdentifier = true
	return c
}

func (c *CertificateBuilder) BuildSelfSignedCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	template, err := c.buildCertificateTemplate()
	if err != nil {
		return nil, nil, err
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, c.bitSize)
	if err != nil {
		return nil, nil, err
	}

	if c.isCertificateAuthority {
		template.IsCA = true
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, rootKey, nil
}

func (c *CertificateBuilder) buildCertificateTemplate() (*x509.Certificate, error) {
	if err := c.ensureSerialNumberIsSet(); err != nil {
		return nil, err
	}
	notBefore, notAfter := c.getNotBeforeAfterPair()
	subject := c.buildSubjectName()
	cert := &x509.Certificate{
		SerialNumber:          c.serialNumber,
		Subject:               *subject,
		BasicConstraintsValid: c.includeBasicConstraint,
		KeyUsage:              c.keyUsage,
		ExtKeyUsage:           c.enhancedKeyUsages,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		Extensions:            c.extensions,
	}
	return cert, nil
}

func (c *CertificateBuilder) getNotBeforeAfterPair() (time.Time, time.Time) {
	notBefore := time.Now()
	if c.notBefore != nil {
		notBefore = *c.notBefore
	}
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	if c.notAfter != nil {
		notAfter = *c.notAfter
	}

	return notBefore, notAfter
}

func (c *CertificateBuilder) ensureSerialNumberIsSet() error {

	if c.serialNumber != nil {
		return nil
	}
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(200000000))
	if err != nil {
		return err
	}
	c.serialNumber = serialNumber
	return nil
}

func (c *CertificateBuilder) buildSubjectName() *pkix.Name {
	name := pkix.Name{
		CommonName: c.commonName,
	}

	if c.organization != "" {
		name.Organization = []string{c.organization}
	}
	if c.organizationUnit != "" {
		name.OrganizationalUnit = []string{c.organizationUnit}
	}
	if c.city != "" {
		name.Locality = []string{c.city}
	}
	if c.state != "" {
		name.Province = []string{c.state}
	}
	if c.country != "" {
		name.Country = []string{c.country}
	}
	return &name
}
