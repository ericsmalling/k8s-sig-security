package state

import (
	"reflect"
	"testing"
)

func TestParseAffectedVersions(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []Versions
		wantError bool
	}{
		{
			name:  "single component without introduced version",
			input: "kube-apiserver < v1.31.12",
			want: []Versions{
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
			},
		},
		{
			name:  "single component with introduced version",
			input: "etcd v3.5.0 < v3.5.8",
			want: []Versions{
				{Component: "etcd", FirstAffectedVersion: "v3.5.0", FixedVersion: "v3.5.8"},
			},
		},
		{
			name: "multiple versions same component",
			input: `kube-apiserver < v1.31.12
kube-apiserver v1.32.0 < v1.32.8
kube-apiserver < v1.33.4`,
			want: []Versions{
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
				{Component: "kube-apiserver", FirstAffectedVersion: "v1.32.0", FixedVersion: "v1.32.8"},
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.33.4"},
			},
		},
		{
			name: "extra spaces and mixed casing",
			input: `

	kube-apiserver    <    v1.31.12
kube-apiserver V1.32.0    <   V1.32.8
`,
			want: []Versions{
				{Component: "kube-apiserver", FirstAffectedVersion: "", FixedVersion: "v1.31.12"},
				{Component: "kube-apiserver", FirstAffectedVersion: "V1.32.0", FixedVersion: "V1.32.8"},
			},
		},
		{
			name:      "mixed components should error",
			input:     "kube-apiserver < v1.31.12\netcd v3.5.0 < v3.5.8",
			want:      []Versions{},
			wantError: true,
		},
		{
			name: "invalid lines",
			input: `kube-apiserver < v1.31.12
invalid line here
kubelet < v1.30.7`,
			want:      []Versions{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAffectedVersions(tt.input)
			if err != nil && !tt.wantError {
				t.Errorf("unexpected error %s", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseGitHubIssueURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      GitHubIssue
		wantError bool
	}{
		{
			name:  "valid https URL",
			input: "https://github.com/kubernetes/kubernetes/issues/12345",
			want: GitHubIssue{
				URL:    "https://github.com/kubernetes/kubernetes/issues/12345",
				Org:    "kubernetes",
				Repo:   "kubernetes",
				Number: "12345",
			},
		},
		{
			name:  "valid http URL",
			input: "http://github.com/kubernetes/kubernetes/issues/12345",
			want: GitHubIssue{
				URL:    "http://github.com/kubernetes/kubernetes/issues/12345",
				Org:    "kubernetes",
				Repo:   "kubernetes",
				Number: "12345",
			},
		},
		{
			name:  "valid URL with trailing slash",
			input: "https://github.com/kubernetes/kubernetes/issues/12345/",
			want: GitHubIssue{
				URL:    "https://github.com/kubernetes/kubernetes/issues/12345/",
				Org:    "kubernetes",
				Repo:   "kubernetes",
				Number: "12345",
			},
		},
		{
			name:  "different org and repo",
			input: "https://github.com/istio/istio/issues/99999",
			want: GitHubIssue{
				URL:    "https://github.com/istio/istio/issues/99999",
				Org:    "istio",
				Repo:   "istio",
				Number: "99999",
			},
		},
		{
			name:      "missing issue number",
			input:     "https://github.com/kubernetes/kubernetes/issues/",
			wantError: true,
		},
		{
			name:      "non-numeric issue number",
			input:     "https://github.com/kubernetes/kubernetes/issues/abc",
			wantError: true,
		},
		{
			name:      "wrong path (pull instead of issues)",
			input:     "https://github.com/kubernetes/kubernetes/pull/12345",
			wantError: true,
		},
		{
			name:      "missing repo",
			input:     "https://github.com/kubernetes/issues/12345",
			wantError: true,
		},
		{
			name:      "not github.com",
			input:     "https://gitlab.com/kubernetes/kubernetes/issues/12345",
			wantError: true,
		},
		{
			name:      "empty string",
			input:     "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGitHubIssueURL(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got none, result: %#v", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %s", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}
