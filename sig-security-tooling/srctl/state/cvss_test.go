package state

import (
	"strings"
	"testing"
)

func TestParseCVSS31(t *testing.T) {
	url := "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
	cvss, err := parseCVSS(url)
	if err != nil {
		t.Fatalf("parseCVSS() error = %v", err)
	}

	if cvss.URL != url {
		t.Errorf("parseCVSS() URL = %q, want %q", cvss.URL, url)
	}
	if cvss.Vector != "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("parseCVSS() Vector = %q", cvss.Vector)
	}
	if cvss.Severity != "HIGH" {
		t.Errorf("parseCVSS() Severity = %q, want %q", cvss.Severity, "HIGH")
	}
	if cvss.Score < 8.0 || cvss.Score > 9.0 {
		t.Errorf("parseCVSS() Score = %f, expected around 8.8", cvss.Score)
	}
}

func TestParseCVSS30(t *testing.T) {
	url := "https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L"
	cvss, err := parseCVSS(url)
	if err != nil {
		t.Fatalf("parseCVSS() error = %v", err)
	}

	if !strings.HasPrefix(cvss.Vector, "CVSS:3.0") {
		t.Errorf("parseCVSS() Vector = %q, expected CVSS:3.0 prefix", cvss.Vector)
	}
	if cvss.Severity == "" {
		t.Error("parseCVSS() Severity should not be empty for CVSS 3.0")
	}
}

func TestParseCVSS40(t *testing.T) {
	url := "https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	cvss, err := parseCVSS(url)
	if err != nil {
		t.Fatalf("parseCVSS() error = %v", err)
	}

	if !strings.HasPrefix(cvss.Vector, "CVSS:4.0") {
		t.Errorf("parseCVSS() Vector = %q, expected CVSS:4.0 prefix", cvss.Vector)
	}
	if cvss.Severity == "" {
		t.Error("parseCVSS() Severity should not be empty for CVSS 4.0")
	}
	if cvss.Score <= 0 {
		t.Error("parseCVSS() Score should be positive for CVSS 4.0")
	}
}

func TestParseCVSSInvalidURL(t *testing.T) {
	_, err := parseCVSS("://invalid-url")
	if err == nil {
		t.Error("parseCVSS() should error on invalid URL")
	}
}

func TestParseCVSSInvalidVector(t *testing.T) {
	_, err := parseCVSS("https://example.com#invalid-vector")
	if err == nil {
		t.Error("parseCVSS() should error on invalid CVSS vector")
	}
}

func TestParseCVSSEmptyFragment(t *testing.T) {
	_, err := parseCVSS("https://example.com")
	if err == nil {
		t.Error("parseCVSS() should error on empty fragment")
	}
}
