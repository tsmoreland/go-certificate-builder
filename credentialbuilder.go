package x509certificates

import (
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
	notBefore                     *time.Time
	notAfter                      *time.Time
	serialNumber                  *big.Int
	includeSubjectKeyIdentifier   bool
	subjectKeyIdentifierCritical  bool
	includeAuthorityKeyIdentifier bool
}

func NewCertificateBuilder() *CertificateBuilder {
	return &CertificateBuilder{
		err:              nil,
		bitSize:          4096,
		commonName:       "",
		organization:     "",
		organizationUnit: "",
		city:             "",
		state:            "",
		country:          "",
		dnsNames:         make([]string, 0, 0),
		notBefore:        nil,
		notAfter:         nil,
		serialNumber:     nil,
	}
}

func (c *CertificateBuilder) WithBitSize(value int) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithCommonName(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithOrganization(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithOrganizationUnit(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithCity(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithState(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithCountry(value string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithDnsNames(value []string) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithNotBefore(value *time.Time) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithNotAfter(value *time.Time) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithSerialNumber(value *big.Int) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithIncludeSubjectKeyIdentifier(value bool) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithSubjectKeyIdentifierCritical(value bool) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}

func (c *CertificateBuilder) WithIncludeAuthorityKeyIdentifier(value bool) *CertificateBuilder {
	if c.err != nil {
		return c
	}
	return c
}
