package k8s_test

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/onsi/gomega/types"
	appV1 "k8s.io/api/apps/v1"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"os/exec"
)

type RenderingContext struct {
	templates []string
	data      map[string]string
}

func (r RenderingContext) WithData(data map[string]string) RenderingContext {
	r.data = data
	return r
}

func NewRenderingContext(templates ...string) RenderingContext {
	return RenderingContext{templates, nil}
}

type ProduceYAMLMatcher struct {
	matcher types.GomegaMatcher
}

func ProduceYAML(matcher types.GomegaMatcher) *ProduceYAMLMatcher {
	return &ProduceYAMLMatcher{matcher}
}

func (matcher *ProduceYAMLMatcher) Match(actual interface{}) (bool, error) {
	rendering, ok := actual.(RenderingContext)
	if !ok {
		return false, fmt.Errorf("ProduceYAML must be passed a RenderingContext. Got\n%s", format.Object(actual, 1))
	}

	session, err := renderWithData(rendering.templates, rendering.data)
	if err != nil {
		return false, err
	}

	obj, err := parseYAML(session.Out)
	if err != nil {
		return false, err
	}

	return matcher.matcher.Match(obj)
}

func (matcher *ProduceYAMLMatcher) FailureMessage(actual interface{}) string {
	return matcher.matcher.FailureMessage(actual)
}

func (matcher *ProduceYAMLMatcher) NegatedFailureMessage(actual interface{}) string {
	return matcher.matcher.NegatedFailureMessage(actual)
}

func renderWithData(templates []string, data map[string]string) (*gexec.Session, error) {
	var args []string
	for _, template := range templates {
		args = append(args, "-f", template)
	}

	for k, v := range data {
		args = append(args, "-v", fmt.Sprintf("%s=%s", k, v))
	}

	command := exec.Command("ytt", args...)
	session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
	if err != nil {
		return session, err
	}

	return session.Wait(), nil
}

func parseYAML(yaml *gbytes.Buffer) (interface{}, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(yaml.Contents(), nil, nil)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

type ContainerExpectation func(coreV1.Container) error

type RepresentingContainerMatcher struct {
	name  string
	tests []ContainerExpectation
	err   error
}

func RepresentingContainer(name string) *RepresentingContainerMatcher {
	return &RepresentingContainerMatcher{name, nil, nil}
}

func (matcher *RepresentingContainerMatcher) Match(actual interface{}) (bool, error) {
	deployment, ok := actual.(*appV1.Deployment)
	if !ok {
		return false, fmt.Errorf("RepresentingContainer must be passed a deployment. Got\n%s", format.Object(actual, 1))
	}

	var selected *coreV1.Container
	for _, c := range deployment.Spec.Template.Spec.Containers {
		if c.Name == matcher.name {
			selected = &c
		}
	}

	if selected == nil {
		matcher.err = fmt.Errorf("Expected container named %s, but did not find one", matcher.name)
		return false, nil
	}

	for _, test := range matcher.tests {
		if err := test(*selected); err != nil {
			matcher.err = err
			return false, nil
		}
	}

	return true, nil
}

func (matcher *RepresentingContainerMatcher) FailureMessage(actual interface{}) string {
	return fmt.Sprintf("Container did not match expectation: %v", matcher.err)
}

func (matcher *RepresentingContainerMatcher) NegatedFailureMessage(actual interface{}) string {
	return fmt.Sprintf("Container should not to match expectation: %v", matcher.err)
}
