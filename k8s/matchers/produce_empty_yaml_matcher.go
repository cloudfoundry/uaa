package matchers

import (
	"fmt"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
)

type ProduceEmptyYAMLMatcher struct {
	matcher  types.GomegaMatcher
	rendered string
}

func ProduceEmptyYAML() *ProduceEmptyYAMLMatcher {
	return &ProduceEmptyYAMLMatcher{
		gomega.BeEmpty(),
		"",
	}
}

func (m *ProduceEmptyYAMLMatcher) Match(actual interface{}) (bool, error) {
	rendering, ok := actual.(RenderingContext)
	if !ok {
		return false, fmt.Errorf("ProduceYAML must be passed a RenderingContext. Got\n%s", format.Object(actual, 1))
	}

	session, err := renderWithData(rendering.templates, rendering.data)
	if err != nil || session.ExitCode() != 0 {
		return false, fmt.Errorf("render error, exit status={%v}, command={%s}, error={%v}", session.ExitCode(), session.Command, err)
	}

	m.rendered = string(session.Out.Contents())

	return m.matcher.Match(m.rendered)
}

func (m *ProduceEmptyYAMLMatcher) FailureMessage(actual interface{}) string {
	msg := fmt.Sprintf(
		"FailureMessage: There is a problem with m YAML:\n\n%s\n\n%s",
		m.rendered,
		m.matcher.FailureMessage(actual),
	)
	return msg
}

func (m *ProduceEmptyYAMLMatcher) NegatedFailureMessage(actual interface{}) string {
	msg := fmt.Sprintf(
		"NegatedFailureMessage: There is a problem with m YAML:\n\n%s\n\n%s",
		m.rendered,
		m.matcher.NegatedFailureMessage(actual),
	)
	return msg
}
