package state

import (
	"testing"
)

func TestStepNumberASCII(t *testing.T) {
	tests := []struct {
		step StepNumber
		want byte
	}{
		{StepSummary, '0'},
		{StepCVSS, '1'},
		{StepDescription, '2'},
		{StepVulnerable, '3'},
		{StepAffectedVersions, '4'},
		{StepUpgrade, '5'},
		{StepMitigate, '6'},
		{StepDetection, '7'},
		{StepAdditionalDetails, '8'},
		{StepAcknowledgements, '9'},
	}

	for _, tt := range tests {
		t.Run(tt.step.Name(), func(t *testing.T) {
			got := tt.step.ASCII()
			if got != tt.want {
				t.Errorf("StepNumber(%d).ASCII() = %c, want %c", tt.step, got, tt.want)
			}
		})
	}
}

func TestStepNumberName(t *testing.T) {
	tests := []struct {
		step StepNumber
		want StepName
	}{
		{StepSummary, "summary"},
		{StepCVSS, "cvss"},
		{StepDescription, "description"},
		{StepVulnerable, "vulnerable"},
		{StepAffectedVersions, "affected_versions"},
		{StepUpgrade, "upgrade"},
		{StepMitigate, "mitigate"},
		{StepDetection, "detection"},
		{StepAdditionalDetails, "additional_details"},
		{StepAcknowledgements, "acknowledgements"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.step.Name()
			if got != tt.want {
				t.Errorf("StepNumber(%d).Name() = %q, want %q", tt.step, got, tt.want)
			}
		})
	}
}

func TestStepNumberNamePanicsOnInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("StepMax.Name() should panic")
		}
	}()
	StepMax.Name()
}

func TestInitStepsComplete(t *testing.T) {
	// Verify all steps are defined in initSteps
	for i := range StepMax {
		name := i.Name()
		step, ok := initSteps[name]
		if !ok {
			t.Errorf("initSteps missing step %q", name)
			continue
		}
		if step.ID != i {
			t.Errorf("initSteps[%q].ID = %d, want %d", name, step.ID, i)
		}
		if step.Title == "" {
			t.Errorf("initSteps[%q].Title is empty", name)
		}
	}
}

func TestSummaryValidation(t *testing.T) {
	step := initSteps[StepSummary.Name()]
	if step.Validate == nil {
		t.Fatal("Summary step should have Validate function")
	}

	// Valid summary
	err := step.Validate("Single line summary")
	if err != nil {
		t.Errorf("Validate() error = %v for valid summary", err)
	}

	// Invalid summary with newline
	err = step.Validate("Line 1\nLine 2")
	if err == nil {
		t.Error("Validate() should error on summary with newline")
	}
}

func TestAffectedVersionsValidation(t *testing.T) {
	step := initSteps[StepAffectedVersions.Name()]
	if step.Validate == nil {
		t.Fatal("AffectedVersions step should have Validate function")
	}

	// Valid versions
	err := step.Validate("kube-apiserver < v1.31.12")
	if err != nil {
		t.Errorf("Validate() error = %v for valid versions", err)
	}

	// Invalid versions
	err = step.Validate("invalid format")
	if err == nil {
		t.Error("Validate() should error on invalid versions format")
	}
}
