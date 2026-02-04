package state

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
)

const (
	reverse    = "\033[7m"
	notReverse = "\033[27m"

	maxWidthDisplay = 60
)

// buildInfo holds version and build information for JSON export.
type buildInfo struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// External is the struct used by the JSON marshaller to export the state to
// files to hide the implementation details to the user.
type external struct {
	CVE       string              `json:"cve"`
	Steps     map[StepName]string `json:"steps"`
	BuildInfo buildInfo           `json:"build_info"`
}

func (s external) toInternal() Internal {
	newInternal := New(s.CVE)
	for key, value := range s.Steps {
		s, ok := newInternal.steps[key]
		if !ok {
			// unknown step, ignore
			continue
		}
		s.Value = value
		newInternal.steps[key] = s
	}
	return newInternal
}

type Internal struct {
	CVE   string
	steps map[StepName]Step

	focus  StepNumber
	status string
	Dirty  bool
}

func New(cve string) Internal {
	// Copy initSteps to avoid sharing the map reference across instances
	steps := make(map[StepName]Step, len(initSteps))
	maps.Copy(steps, initSteps)
	return Internal{
		CVE:   cve,
		steps: steps,
		focus: StepSummary,
	}
}

func (s Internal) String() string {
	out := &strings.Builder{}
	fmt.Fprintf(out, "%s\n", s.CVE)

	for stepNumber := range StepMax {
		step := s.steps[stepNumber.Name()]
		if step.ID == s.GetFocus() {
			fmt.Fprintf(out, "(%s%c%s) ", reverse, step.ID.ASCII(), notReverse)
		} else {
			fmt.Fprintf(out, "(%c) ", step.ID.ASCII())
		}
		fmt.Fprintf(out, "%s: ", step.Title)
		if step.Value != "" {
			fmt.Fprintf(out, "%q", truncateMiddle(step.Value, maxWidthDisplay))
		}
		fmt.Fprintf(out, "\n")
	}
	return out.String()
}

func (s Internal) GetCurrentStep() Step {
	return s.steps[s.GetFocus().Name()]
}

func (s *Internal) SetCurrentStep(step Step) {
	s.steps[s.GetFocus().Name()] = step
	s.Dirty = true
}

func (s *Internal) NextFocus() {
	s.focus = (s.focus + 1) % StepMax
}

func (s *Internal) PreviousFocus() {
	s.focus = (s.focus - 1 + StepMax) % StepMax
}

func (s *Internal) GoToFocus(n StepNumber) StepNumber {
	s.focus = n % StepMax
	return s.focus
}

func (s Internal) GetFocus() StepNumber {
	return s.focus
}

func (s *Internal) SetStatus(message string) {
	s.status = message
}

func (s *Internal) ClearStatus() {
	s.status = ""
}

func (s Internal) GetStatus() string {
	return s.status
}

func (s Internal) toExternal() external {
	var newExternal external
	newExternal.CVE = s.CVE
	newExternal.Steps = map[StepName]string{}
	for key, step := range s.steps {
		newExternal.Steps[key] = step.Value
	}
	newExternal.BuildInfo = buildInfo{
		Version:   Version,
		GitCommit: GitCommit + GitDirty,
		BuildTime: BuildTime,
		GoVersion: GoVersion,
	}
	return newExternal
}

func (s Internal) ToJSON() ([]byte, error) {
	externalState := s.toExternal()
	b, err := json.MarshalIndent(externalState, "", "	")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal indent to JSON: %w", err)
	}
	return b, nil
}

func (s *Internal) ExportToFile() error {
	bytes, err := s.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to convert to JSON: %w", err)
	}

	file, err := os.Create(s.CVE + ".json")
	if err != nil {
		return fmt.Errorf("failed to create new file %s: %w", s.CVE, err)
	}

	_, writeErr := file.Write(bytes)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("failed to write to file %s: %w", file.Name(), writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close file %s: %w", file.Name(), closeErr)
	}
	s.Dirty = false
	return nil
}

func RestoreFromFile(file *os.File, cve string) (Internal, error) {
	bytes, err := io.ReadAll(file)
	if err != nil {
		return Internal{}, fmt.Errorf("failed to read file %s: %w", file.Name(), err)
	}

	var stateFromFile external
	err = json.Unmarshal(bytes, &stateFromFile)
	if err != nil {
		return Internal{}, fmt.Errorf("failed to unmarshal from file %s: %w", file.Name(), err)
	}

	if cve != stateFromFile.CVE {
		return Internal{}, fmt.Errorf("CVE provided %s and from file %s don't match", cve, stateFromFile.CVE)
	}

	for _, step := range stateFromFile.toInternal().steps {
		if step.Validate != nil {
			err := step.Validate(step.Value)
			if err != nil {
				return Internal{}, fmt.Errorf("failed validating value from step %s from file %s: %w", step.ID.Name(), file.Name(), err)
			}
		}
	}

	return stateFromFile.toInternal(), nil
}

func truncateMiddle(s string, maximum int) string {
	if len(s) <= maximum || maximum <= 0 {
		return s
	}

	ellipsis := "[...]"
	if maximum <= len(ellipsis) {
		// max is too small to fit ellipsis, just truncate hard
		return s[:maximum]
	}

	// Remaining space for start + end
	remain := maximum - len(ellipsis)
	startLen := remain / 2
	endLen := remain - startLen

	return s[:startLen] + ellipsis + s[len(s)-endLen:]
}
