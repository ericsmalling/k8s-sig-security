package state

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	testCVE           = "CVE-2024-1234"
	testSchemaVersion = "1.6.0"
)

func TestToOSV(t *testing.T) {
	data := CVEData{
		CVE:     testCVE,
		Summary: "Buffer overflow in kube-apiserver",
		CVSS: CVSS{
			URL:      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Severity: "HIGH",
			Score:    8.8,
		},
		Description: "A vulnerability was found in kube-apiserver.",
		Versions: []Versions{
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.30.0", FixedVersion: "v1.31.12"},
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.32.0", FixedVersion: "v1.32.8"},
		},
		Acknowledgements: "Security Researcher",
	}

	osv := data.ToOSV()

	if osv.SchemaVersion != testSchemaVersion {
		t.Errorf("ToOSV() SchemaVersion = %q, want %q", osv.SchemaVersion, testSchemaVersion)
	}
	if osv.ID != testCVE {
		t.Errorf("ToOSV() ID = %q, want %q", osv.ID, testCVE)
	}
	if osv.Summary != "Buffer overflow in kube-apiserver" {
		t.Errorf("ToOSV() Summary = %q", osv.Summary)
	}
	if osv.Details != "A vulnerability was found in kube-apiserver." {
		t.Errorf("ToOSV() Details = %q", osv.Details)
	}
	if osv.Modified == "" {
		t.Error("ToOSV() Modified should not be empty")
	}
}

func TestToOSVSeverityCVSS31(t *testing.T) {
	data := CVEData{
		CVE: testCVE,
		CVSS: CVSS{
			Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		},
	}

	osv := data.ToOSV()

	if len(osv.Severity) != 1 {
		t.Fatalf("ToOSV() Severity length = %d, want 1", len(osv.Severity))
	}
	if osv.Severity[0].Type != "CVSS_V3" {
		t.Errorf("ToOSV() Severity[0].Type = %q, want %q", osv.Severity[0].Type, "CVSS_V3")
	}
	if osv.Severity[0].Score != "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("ToOSV() Severity[0].Score = %q", osv.Severity[0].Score)
	}
}

func TestToOSVSeverityCVSS40(t *testing.T) {
	data := CVEData{
		CVE: testCVE,
		CVSS: CVSS{
			Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		},
	}

	osv := data.ToOSV()

	if len(osv.Severity) != 1 {
		t.Fatalf("ToOSV() Severity length = %d, want 1", len(osv.Severity))
	}
	if osv.Severity[0].Type != "CVSS_V4" {
		t.Errorf("ToOSV() Severity[0].Type = %q, want %q", osv.Severity[0].Type, "CVSS_V4")
	}
}

func TestToOSVSeverityCVSS20(t *testing.T) {
	data := CVEData{
		CVE: testCVE,
		CVSS: CVSS{
			Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		},
	}

	osv := data.ToOSV()

	if len(osv.Severity) != 1 {
		t.Fatalf("ToOSV() Severity length = %d, want 1", len(osv.Severity))
	}
	if osv.Severity[0].Type != "CVSS_V2" {
		t.Errorf("ToOSV() Severity[0].Type = %q, want %q", osv.Severity[0].Type, "CVSS_V2")
	}
}

func TestToOSVAffected(t *testing.T) {
	data := CVEData{
		CVE: testCVE,
		Versions: []Versions{
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.30.0", FixedVersion: "v1.31.12"},
		},
	}

	osv := data.ToOSV()

	if len(osv.Affected) != 1 {
		t.Fatalf("ToOSV() Affected length = %d, want 1", len(osv.Affected))
	}

	affected := osv.Affected[0]
	if affected.Package.Ecosystem != "Kubernetes" {
		t.Errorf("ToOSV() Affected[0].Package.Ecosystem = %q, want %q", affected.Package.Ecosystem, "Kubernetes")
	}
	if affected.Package.Name != "kube-apiserver" {
		t.Errorf("ToOSV() Affected[0].Package.Name = %q, want %q", affected.Package.Name, "kube-apiserver")
	}
	if len(affected.Ranges) != 1 {
		t.Fatalf("ToOSV() Affected[0].Ranges length = %d, want 1", len(affected.Ranges))
	}
	if affected.Ranges[0].Type != "SEMVER" {
		t.Errorf("ToOSV() Affected[0].Ranges[0].Type = %q, want %q", affected.Ranges[0].Type, "SEMVER")
	}
	if len(affected.Ranges[0].Events) != 2 {
		t.Fatalf("ToOSV() Affected[0].Ranges[0].Events length = %d, want 2", len(affected.Ranges[0].Events))
	}
	if affected.Ranges[0].Events[0].Introduced != "v1.30.0" {
		t.Errorf("ToOSV() Events[0].Introduced = %q, want %q", affected.Ranges[0].Events[0].Introduced, "v1.30.0")
	}
	if affected.Ranges[0].Events[1].Fixed != "v1.31.12" {
		t.Errorf("ToOSV() Events[1].Fixed = %q, want %q", affected.Ranges[0].Events[1].Fixed, "v1.31.12")
	}
}

func TestToOSVAffectedNoIntroducedVersion(t *testing.T) {
	data := CVEData{
		CVE: testCVE,
		Versions: []Versions{
			{Component: "kubelet", FixedVersion: "v1.30.7"},
		},
	}

	osv := data.ToOSV()

	if len(osv.Affected) != 1 {
		t.Fatalf("ToOSV() Affected length = %d, want 1", len(osv.Affected))
	}

	events := osv.Affected[0].Ranges[0].Events
	if events[0].Introduced != "0" {
		t.Errorf("ToOSV() Events[0].Introduced = %q, want %q (default)", events[0].Introduced, "0")
	}
	if events[1].Fixed != "v1.30.7" {
		t.Errorf("ToOSV() Events[1].Fixed = %q, want %q", events[1].Fixed, "v1.30.7")
	}
}

func TestToOSVReferences(t *testing.T) {
	data := CVEData{
		CVE: testCVE,
		CVSS: CVSS{
			URL:    "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		},
	}

	osv := data.ToOSV()

	if len(osv.References) != 1 {
		t.Fatalf("ToOSV() References length = %d, want 1", len(osv.References))
	}
	if osv.References[0].Type != "WEB" {
		t.Errorf("ToOSV() References[0].Type = %q, want %q", osv.References[0].Type, "WEB")
	}
	if osv.References[0].URL != "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("ToOSV() References[0].URL = %q", osv.References[0].URL)
	}
}

func TestToOSVCredits(t *testing.T) {
	data := CVEData{
		CVE:              testCVE,
		Acknowledgements: "Security Researcher",
	}

	osv := data.ToOSV()

	if len(osv.Credits) != 1 {
		t.Fatalf("ToOSV() Credits length = %d, want 1", len(osv.Credits))
	}
	if osv.Credits[0].Name != "Security Researcher" {
		t.Errorf("ToOSV() Credits[0].Name = %q, want %q", osv.Credits[0].Name, "Security Researcher")
	}
	if osv.Credits[0].Type != "FINDER" {
		t.Errorf("ToOSV() Credits[0].Type = %q, want %q", osv.Credits[0].Type, "FINDER")
	}
}

func TestToOSVJSON(t *testing.T) {
	data := CVEData{
		CVE:     "CVE-2024-5678",
		Summary: "Test vulnerability",
	}

	jsonBytes, err := data.ToOSVJSON()
	if err != nil {
		t.Fatalf("ToOSVJSON() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		t.Fatalf("ToOSVJSON() produced invalid JSON: %v", err)
	}

	if result["id"] != "CVE-2024-5678" {
		t.Errorf("ToOSVJSON() id = %v, want %q", result["id"], "CVE-2024-5678")
	}
	if result["summary"] != "Test vulnerability" {
		t.Errorf("ToOSVJSON() summary = %v, want %q", result["summary"], "Test vulnerability")
	}
	if result["schema_version"] != "1.6.0" {
		t.Errorf("ToOSVJSON() schema_version = %v, want %q", result["schema_version"], "1.6.0")
	}
}

func TestOSVString(t *testing.T) {
	data := CVEData{
		CVE:     "CVE-2024-9999",
		Summary: "String test",
	}

	str := data.OSVString()

	if str == "" {
		t.Error("OSVString() should not be empty")
	}
	if !strings.Contains(str, "CVE-2024-9999") {
		t.Error("OSVString() should contain CVE ID")
	}
	if !strings.Contains(str, "String test") {
		t.Error("OSVString() should contain summary")
	}
}

func TestToOSVEmptyData(t *testing.T) {
	data := CVEData{
		CVE: "CVE-2024-0000",
	}

	osv := data.ToOSV()

	if osv.ID != "CVE-2024-0000" {
		t.Errorf("ToOSV() ID = %q, want %q", osv.ID, "CVE-2024-0000")
	}
	if len(osv.Severity) != 0 {
		t.Errorf("ToOSV() Severity should be empty, got %d", len(osv.Severity))
	}
	if len(osv.Affected) != 0 {
		t.Errorf("ToOSV() Affected should be empty, got %d", len(osv.Affected))
	}
	if len(osv.References) != 0 {
		t.Errorf("ToOSV() References should be empty, got %d", len(osv.References))
	}
	if len(osv.Credits) != 0 {
		t.Errorf("ToOSV() Credits should be empty, got %d", len(osv.Credits))
	}
}

// TestOSVOfficialSchemaCompatibility validates that our OSV output can be
// parsed by the official OSSF OSV schema library.
func TestOSVOfficialSchemaCompatibility(t *testing.T) {
	data := CVEData{
		CVE:     testCVE,
		Summary: "Buffer overflow in kube-apiserver",
		CVSS: CVSS{
			URL:      "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Severity: "HIGH",
			Score:    8.8,
		},
		Description: "A vulnerability was found in kube-apiserver.",
		Versions: []Versions{
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.30.0", FixedVersion: "v1.31.12"},
			{Component: "kube-apiserver", FirstAffectedVersion: "v1.32.0", FixedVersion: "v1.32.8"},
		},
		Acknowledgements: "Security Researcher",
	}

	jsonBytes, err := data.ToOSVJSON()
	if err != nil {
		t.Fatalf("ToOSVJSON() error = %v", err)
	}

	// Parse with official OSSF OSV schema library
	var official osvschema.Vulnerability
	err = protojson.Unmarshal(jsonBytes, &official)
	if err != nil {
		t.Fatalf("Official OSV schema failed to parse our output: %v\nJSON:\n%s", err, string(jsonBytes))
	}

	// Verify key fields were parsed correctly
	if official.GetId() != testCVE {
		t.Errorf("Official parser ID = %q, want %q", official.GetId(), testCVE)
	}
	if official.GetSummary() != "Buffer overflow in kube-apiserver" {
		t.Errorf("Official parser Summary = %q", official.GetSummary())
	}
	if official.GetDetails() != "A vulnerability was found in kube-apiserver." {
		t.Errorf("Official parser Details = %q", official.GetDetails())
	}
	if official.GetSchemaVersion() != testSchemaVersion {
		t.Errorf("Official parser SchemaVersion = %q, want %q", official.GetSchemaVersion(), testSchemaVersion)
	}
	if len(official.GetAffected()) == 0 {
		t.Error("Official parser Affected should not be empty")
	}
	if len(official.GetSeverity()) == 0 {
		t.Error("Official parser Severity should not be empty")
	}
	if len(official.GetCredits()) == 0 {
		t.Error("Official parser Credits should not be empty")
	}
}
