package state

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"
)

var (
	//go:embed issue.tmpl
	rawIssueTemplate string
	issueTemplate    = template.Must(template.New("issue").Parse(rawIssueTemplate))

	//go:embed slack.tmpl
	rawSlackTemplate string
	slackTemplate    = template.Must(template.New("slack").Parse(rawSlackTemplate))

	//go:embed email.tmpl
	rawEmailTemplate string
	emailTemplate    = template.Must(template.New("email").Parse(rawEmailTemplate))
)

func (d CVEData) toFormatWithTemplate(template *template.Template) ([]byte, error) {
	var buf bytes.Buffer

	err := template.Execute(&buf, d)
	if err != nil {
		return nil, fmt.Errorf("failed to execute the template: %w", err)
	}
	return buf.Bytes(), nil
}

func (d CVEData) ToIssue() ([]byte, error) {
	return d.toFormatWithTemplate(issueTemplate)
}

func (d CVEData) ToSlack() ([]byte, error) {
	return d.toFormatWithTemplate(slackTemplate)
}

func (d CVEData) ToEmail() ([]byte, error) {
	return d.toFormatWithTemplate(emailTemplate)
}
