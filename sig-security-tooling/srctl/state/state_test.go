package state

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	cve := "CVE-2024-1234"
	st := New(cve)

	if st.CVE != cve {
		t.Errorf("New() CVE = %q, want %q", st.CVE, cve)
	}
	if st.focus != StepSummary {
		t.Errorf("New() focus = %d, want %d", st.focus, StepSummary)
	}
	if st.Dirty {
		t.Error("New() Dirty should be false")
	}
	if len(st.steps) != int(StepMax) {
		t.Errorf("New() steps count = %d, want %d", len(st.steps), StepMax)
	}
}

func TestNewDoesNotShareMap(t *testing.T) {
	st1 := New("CVE-2024-0001")
	st2 := New("CVE-2024-0002")

	// Modify st1's step
	step := st1.GetCurrentStep()
	step.Value = "modified"
	st1.SetCurrentStep(step)

	// st2 should not be affected
	if st2.GetCurrentStep().Value == "modified" {
		t.Error("New() should not share steps map between instances")
	}
}

func TestFocusNavigation(t *testing.T) {
	st := New("CVE-2024-1234")

	if st.GetFocus() != StepSummary {
		t.Errorf("GetFocus() = %d, want %d", st.GetFocus(), StepSummary)
	}

	st.NextFocus()
	if st.GetFocus() != StepCVSS {
		t.Errorf("NextFocus() focus = %d, want %d", st.GetFocus(), StepCVSS)
	}

	st.PreviousFocus()
	if st.GetFocus() != StepSummary {
		t.Errorf("PreviousFocus() focus = %d, want %d", st.GetFocus(), StepSummary)
	}

	// Test wrap around forward
	for range StepMax {
		st.NextFocus()
	}
	if st.GetFocus() != StepSummary {
		t.Errorf("NextFocus() wrap around focus = %d, want %d", st.GetFocus(), StepSummary)
	}

	// Test wrap around backward
	st.PreviousFocus()
	if st.GetFocus() != StepFixLead {
		t.Errorf("PreviousFocus() wrap around focus = %d, want %d", st.GetFocus(), StepFixLead)
	}
}

func TestGoToFocus(t *testing.T) {
	st := New("CVE-2024-1234")

	result := st.GoToFocus(StepDetection)
	if result != StepDetection {
		t.Errorf("GoToFocus() returned %d, want %d", result, StepDetection)
	}
	if st.GetFocus() != StepDetection {
		t.Errorf("GoToFocus() focus = %d, want %d", st.GetFocus(), StepDetection)
	}

	// Test modulo behavior
	result = st.GoToFocus(StepMax + 2)
	expected := StepNumber(2)
	if result != expected {
		t.Errorf("GoToFocus() with overflow returned %d, want %d", result, expected)
	}
}

func TestStatus(t *testing.T) {
	st := New("CVE-2024-1234")

	if st.GetStatus() != "" {
		t.Errorf("GetStatus() = %q, want empty", st.GetStatus())
	}

	st.SetStatus("test message")
	if st.GetStatus() != "test message" {
		t.Errorf("GetStatus() = %q, want %q", st.GetStatus(), "test message")
	}

	st.ClearStatus()
	if st.GetStatus() != "" {
		t.Errorf("ClearStatus() status = %q, want empty", st.GetStatus())
	}
}

func TestGetSetCurrentStep(t *testing.T) {
	st := New("CVE-2024-1234")

	step := st.GetCurrentStep()
	if step.ID != StepSummary {
		t.Errorf("GetCurrentStep() ID = %d, want %d", step.ID, StepSummary)
	}

	step.Value = "test value"
	st.SetCurrentStep(step)

	if !st.Dirty {
		t.Error("SetCurrentStep() should set Dirty to true")
	}

	retrieved := st.GetCurrentStep()
	if retrieved.Value != "test value" {
		t.Errorf("GetCurrentStep() Value = %q, want %q", retrieved.Value, "test value")
	}
}

func TestString(t *testing.T) {
	st := New("CVE-2024-1234")
	str := st.String()

	if !strings.Contains(str, "CVE-2024-1234") {
		t.Error("String() should contain CVE")
	}
	if !strings.Contains(str, "Summary") {
		t.Error("String() should contain step titles")
	}
}

func TestToJSON(t *testing.T) {
	st := New("CVE-2024-1234")
	step := st.GetCurrentStep()
	step.Value = "test summary"
	st.SetCurrentStep(step)

	jsonBytes, err := st.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		t.Fatalf("ToJSON() produced invalid JSON: %v", err)
	}

	if result["cve"] != "CVE-2024-1234" {
		t.Errorf("ToJSON() cve = %v, want %q", result["cve"], "CVE-2024-1234")
	}

	steps, ok := result["steps"].(map[string]any)
	if !ok {
		t.Fatal("ToJSON() steps is not a map")
	}
	if steps["summary"] != "test summary" {
		t.Errorf("ToJSON() summary = %v, want %q", steps["summary"], "test summary")
	}
}

func TestExportAndRestoreFromFile(t *testing.T) {
	// Create a state and export it
	st := New("CVE-2024-9999")
	step := st.GetCurrentStep()
	step.Value = "exported summary"
	st.SetCurrentStep(step)

	err := st.ExportToFile()
	if err != nil {
		t.Fatalf("ExportToFile() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove("CVE-2024-9999.json"); err != nil {
			t.Errorf("failed to remove test file: %v", err)
		}
	})

	if st.Dirty {
		t.Error("ExportToFile() should set Dirty to false")
	}

	// Restore from file
	file, err := os.Open("CVE-2024-9999.json")
	if err != nil {
		t.Fatalf("Failed to open exported file: %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("failed to close file: %v", err)
		}
	})

	restored, err := RestoreFromFile(file, "CVE-2024-9999")
	if err != nil {
		t.Fatalf("RestoreFromFile() error = %v", err)
	}

	if restored.CVE != "CVE-2024-9999" {
		t.Errorf("RestoreFromFile() CVE = %q, want %q", restored.CVE, "CVE-2024-9999")
	}

	restoredStep := restored.GetCurrentStep()
	if restoredStep.Value != "exported summary" {
		t.Errorf("RestoreFromFile() summary = %q, want %q", restoredStep.Value, "exported summary")
	}
}

func TestRestoreFromFileCVEMismatch(t *testing.T) {
	st := New("CVE-2024-1111")
	err := st.ExportToFile()
	if err != nil {
		t.Fatalf("ExportToFile() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove("CVE-2024-1111.json"); err != nil {
			t.Errorf("failed to remove test file: %v", err)
		}
	})

	file, err := os.Open("CVE-2024-1111.json")
	if err != nil {
		t.Fatalf("Failed to open exported file: %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("failed to close file: %v", err)
		}
	})

	_, err = RestoreFromFile(file, "CVE-2024-2222")
	if err == nil {
		t.Error("RestoreFromFile() should error on CVE mismatch")
	}
	if !strings.Contains(err.Error(), "don't match") {
		t.Errorf("RestoreFromFile() error = %v, want error about mismatch", err)
	}
}

func TestTruncateMiddle(t *testing.T) {
	tests := []struct {
		name  string
		input string
		max   int
		want  string
	}{
		{
			name:  "short string unchanged",
			input: "hello",
			max:   10,
			want:  "hello",
		},
		{
			name:  "exact length unchanged",
			input: "hello",
			max:   5,
			want:  "hello",
		},
		{
			name:  "long string truncated",
			input: "hello world this is a long string",
			max:   20,
			want:  "hello w[...]g string",
		},
		{
			name:  "max zero returns original",
			input: "hello",
			max:   0,
			want:  "hello",
		},
		{
			name:  "max negative returns original",
			input: "hello",
			max:   -5,
			want:  "hello",
		},
		{
			name:  "max smaller than ellipsis",
			input: "hello world",
			max:   3,
			want:  "hel",
		},
		{
			name:  "max equal to ellipsis length",
			input: "hello world",
			max:   5,
			want:  "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateMiddle(tt.input, tt.max)
			if got != tt.want {
				t.Errorf("truncateMiddle(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
			}
		})
	}
}
