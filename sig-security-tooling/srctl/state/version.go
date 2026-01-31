package state

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the current version of srctl.
const Version = "1.0.0"

// Build information populated from runtime/debug.
var (
	GitCommit = ""
	GitDirty  = ""
	BuildTime = ""
	GoVersion = runtime.Version()
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			GitCommit = setting.Value
			if len(GitCommit) > 12 {
				GitCommit = GitCommit[:12]
			}
		case "vcs.modified":
			if setting.Value == "true" {
				GitDirty = "-dirty"
			}
		case "vcs.time":
			BuildTime = setting.Value
		}
	}
}

// BuildInfoString returns a formatted string with version and build information.
// Format: v1.0.0 (abc1234, 2026-01-31T16:00:00Z, go1.23.0).
func BuildInfoString() string {
	var sb strings.Builder
	sb.WriteString("v")
	sb.WriteString(Version)
	if GitCommit != "" || BuildTime != "" || GoVersion != "" {
		sb.WriteString(" (")
		parts := []string{}
		if GitCommit != "" {
			parts = append(parts, GitCommit+GitDirty)
		}
		if BuildTime != "" {
			parts = append(parts, BuildTime)
		}
		if GoVersion != "" {
			parts = append(parts, GoVersion)
		}
		sb.WriteString(strings.Join(parts, ", "))
		sb.WriteString(")")
	}
	return sb.String()
}
