package x509certificates

import (
	"fmt"
	"testing"
)

func TestCertificateBuilder_WithBitSizeShouldReturnNotUpdateBitSizeWhenBuilderHasError(t *testing.T) {
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
