package main

import (
	"strings"
	"testing"

	"k8s.io/kubernetes/sig-security/srctl/state"
)

func TestInstructions(t *testing.T) {
	result := instructions(state.StepSummary, "Summary", "Help text", "Example text")

	str := string(result)

	if !strings.Contains(str, "<!--") {
		t.Error("instructions() should contain HTML comment start")
	}
	if !strings.Contains(str, "-->") {
		t.Error("instructions() should contain HTML comment end")
	}
	if !strings.Contains(str, "0) Summary") {
		t.Error("instructions() should contain step number and title")
	}
	if !strings.Contains(str, "Help text") {
		t.Error("instructions() should contain help text")
	}
	if !strings.Contains(str, "Example:") {
		t.Error("instructions() should contain Example header")
	}
	if !strings.Contains(str, "Example text") {
		t.Error("instructions() should contain example text")
	}
}

func TestInstructionsMultilineHelp(t *testing.T) {
	result := instructions(state.StepCVSS, "CVSS", "Line 1\nLine 2\nLine 3", "Example")

	str := string(result)

	if !strings.Contains(str, "Line 1") {
		t.Error("instructions() should contain first line of help")
	}
	if !strings.Contains(str, "Line 2") {
		t.Error("instructions() should contain second line of help")
	}
	if !strings.Contains(str, "Line 3") {
		t.Error("instructions() should contain third line of help")
	}
}

func TestFirstAvailableEditor(t *testing.T) {
	// Test with common editors that should exist on most systems
	candidates := []string{"nonexistent-editor-12345", "sh", "echo"}
	editor, found := firstAvailableEditor(candidates)

	// sh should exist on all Unix systems
	if found {
		if editor != "sh" && editor != "echo" {
			t.Errorf("firstAvailableEditor() = %q, expected sh or echo", editor)
		}
	}
}

func TestFirstAvailableEditorNoneFound(t *testing.T) {
	candidates := []string{"nonexistent1", "nonexistent2", "nonexistent3"}
	editor, found := firstAvailableEditor(candidates)

	if found {
		t.Errorf("firstAvailableEditor() found = true, want false")
	}
	if editor != "" {
		t.Errorf("firstAvailableEditor() = %q, want empty", editor)
	}
}

func TestFirstAvailableEditorEmptyList(t *testing.T) {
	editor, found := firstAvailableEditor([]string{})

	if found {
		t.Error("firstAvailableEditor() with empty list should return false")
	}
	if editor != "" {
		t.Errorf("firstAvailableEditor() = %q, want empty", editor)
	}
}
