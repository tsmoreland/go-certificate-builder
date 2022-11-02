package x509certificates

import (
	"fmt"
	"testing"
)

func TestCertificateBuilder_GetErrorShouldReturnCurrentError(t *testing.T) {
	c := NewCertificateBuilder()
	expected := fmt.Errorf("sample err")
	c.err = expected
	actual := c.GetError()
	if actual != expected {
		t.Fatalf("Error %v does not match expected value %v", actual, expected)
	}

}

func TestCertificateBuilder_WithBitSizeShouldNotUpdateBitSizeWhenBuilderHasError(t *testing.T) {
	c := NewCertificateBuilder()
	expected := c.bitSize
	c.err = fmt.Errorf("existing-error")

	c.WithBitSize(2048 + expected)

	if c.bitSize != expected {
		t.Fatal("bit size was updated when error was present")
	}

}

func TestCertificateBuilder_WithBitSizeShouldSetErrorWhenValueIsLessThan2048(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithBitSize(2047)

	if c.err == nil {
		t.Fatal("Error was not set when bit size was less than minimum (2048)")
	}
}

func TestCertificateBuilder_WithBitSizeShouldSetBitSizeWhenValueIsInRangeAndErrorNotPresent(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithBitSize(2048)

	if c.err != nil {
		t.Fatal(c.err)
	}

	if c.bitSize != 2048 {
		t.Fatalf("bit size %v does not have expected value of 2048", c.bitSize)
	}
}

func TestCertificateBuilder_WithIsCertificateAuthority_ShouldNotUpdateIsCertificateAuthorityWhenBuilderHasError(t *testing.T) {
	c := NewCertificateBuilder()
	c.err = fmt.Errorf("simple err")
	expected := c.isCertificateAuthority
	c.WithIsCertificateAuthority(!expected)

	if c.isCertificateAuthority != expected {
		t.Fatalf("is Certificate authority was updated to %v", c.isCertificateAuthority)
	}

}

func TestCertificateBuilder_WithIsCertificateAuthorityShouldSetIsCertificateAuthorityWhenBuildDoesNotHaveError(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithIsCertificateAuthority(true)
	actual := c.isCertificateAuthority

	if actual != true {
		t.Fatal("isCertificateAuthority was not updated")
	}
}

func TestCertificateBuilder_WithCommonNameShouldNotUpdateCommonNameWhenBuilderHasError(t *testing.T) {
	c := NewCertificateBuilder()
	c.err = fmt.Errorf("sample error")
	c.WithCommonName("localhost")

	if c.commonName == "localhost" {
		t.Fatal("Common name was updated when builder had error")
	}

}

func TestCertificateBuilder_WithCommonNameShouldNotUpdateCommonNameWhenValueIsEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithCommonName("localhost")
	c.WithCommonName("")
	if c.commonName == "" {
		t.Fatal("Common name did not reject empty name")
	}

}

func TestCertificateBuilder_WithCommonNameShouldSetErrorWhenValueIsEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithCommonName("")
	if c.err == nil {
		t.Fatal("error was not set when common name was set to empty string")
	}
}

func TestCertificateBuilder_WithCommonNameShouldUpdateCommonNameWhenBuilderDoesNotHaveErrorAndValueIsNotEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithCommonName("localhost")
	if c.commonName != "localhost" {
		t.Fatal("Common name was not updated when name was valid and no error present")
	}
	if c.err != nil {
		t.Fatal(c.err)
	}
}

func TestCertificateBuilder_WithOrganizationShouldNotUpdateOrganizationWhenBuilderHasError(t *testing.T) {
	c := NewCertificateBuilder()
	c.err = fmt.Errorf("sample error")
	c.WithOrganization("Acme.")

	if c.organization == "Acme." {
		t.Fatal("Organization was updated when builder had error")
	}

}

func TestCertificateBuilder_WithOrganizationShouldNotUpdateOrganizationWhenValueIsEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithOrganization("Acme.")
	c.WithOrganization("")
	if c.organization == "" {
		t.Fatal("Organization did not reject empty name")
	}

}

func TestCertificateBuilder_WithOrganizationShouldSetErrorWhenValueIsEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithOrganization("")
	if c.err == nil {
		t.Fatal("error was not set when organization was set to empty string")
	}
}

func TestCertificateBuilder_WithOrganizationShouldUpdateOrganizationWhenBuilderDoesNotHaveErrorAndValueIsNotEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithOrganization("Acme.")
	if c.organization != "Acme." {
		t.Fatal("Organization was not updated when name was valid and no error present")
	}
	if c.err != nil {
		t.Fatal(c.err)
	}
}

func TestCertificateBuilder_WithOrganizationUnitShouldNotUpdateOrganizationUnitWhenBuilderHasError(t *testing.T) {
	c := NewCertificateBuilder()
	c.err = fmt.Errorf("sample error")
	c.WithOrganizationUnit("Dynamite Lab")

	if c.organization == "Acme." {
		t.Fatal("Organization Unit was updated when builder had error")
	}

}

func TestCertificateBuilder_WithOrganizationUnitShouldNotUpdateOrganizationUnitWhenValueIsEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithOrganizationUnit("Dynamite Lab")
	c.WithOrganizationUnit("")
	if c.organizationUnit == "" {
		t.Fatal("Organization Unit did not reject empty name")
	}

}

func TestCertificateBuilder_WithOrganizationUnitShouldSetErrorWhenValueIsEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithOrganizationUnit("")
	if c.err == nil {
		t.Fatal("error was not set when organization was set to empty string")
	}
}

func TestCertificateBuilder_WithOrganizationUnitShouldUpdateOrganizationUnitWhenBuilderDoesNotHaveErrorAndValueIsNotEmpty(t *testing.T) {
	c := NewCertificateBuilder()
	c.WithOrganizationUnit("Dynamite Lab")
	if c.organizationUnit != "Dynamite Lab" {
		t.Fatal("Organization Unit was not updated when name was valid and no error present")
	}
	if c.err != nil {
		t.Fatal(c.err)
	}
}
