package matchers

import (
	"fmt"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

type ThrowErrorMatcher struct {
	text string
}

func ThrowError(text string) *ThrowErrorMatcher {
	return &ThrowErrorMatcher{text: text}
}

func (matcher *ThrowErrorMatcher) Match(actual interface{}) (bool, error) {
	rendering, ok := actual.(RenderingContext)
	if !ok {
		return false, fmt.Errorf("ThrowErrorMatcher must be passed a RenderingContext. Got\n%s", format.Object(actual, 1))
	}

	session, _ := renderWithData(rendering.templates, rendering.data)
	if session == nil {
		return false, fmt.Errorf("ThrowErrorMatcher received a nil render session")
	}

	gomega.Eventually(session.Err).Should(gbytes.Say(matcher.text))
	return gomega.Eventually(session).Should(gexec.Exit(1)), nil
}

func (matcher *ThrowErrorMatcher) FailureMessage(actual interface{}) string {
	return "ThrowErrorMatcher FailureMessage not implemented"
}

func (matcher *ThrowErrorMatcher) NegatedFailureMessage(actual interface{}) string {
	return "ThrowErrorMatcher NegatedFailureMessage not implemented"
}
