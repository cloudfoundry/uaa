package k8s_test

import (
	"fmt"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	coreV1 "k8s.io/api/core/v1"
)

type ContainerMatcher struct {
	fields map[string]types.GomegaMatcher

	container *coreV1.Container
	executed  types.GomegaMatcher
}

func NewContainerMatcher() *ContainerMatcher {
	return &ContainerMatcher{map[string]types.GomegaMatcher{}, nil, nil}
}

func (matcher *ContainerMatcher) WithName(name string) *ContainerMatcher {
	matcher.fields["Name"] = gomega.Equal(name)

	return matcher
}

func (matcher *ContainerMatcher) Match(actual interface{}) (bool, error) {
	container, ok := actual.(coreV1.Container)
	if !ok {
		return false, fmt.Errorf("Expected a container. Got\n%s", format.Object(actual, 1))
	}

	matcher.container = &container
	matcher.executed = gstruct.MatchFields(gstruct.IgnoreExtras, matcher.fields)
	return matcher.executed.Match(container)
}

func (matcher *ContainerMatcher) FailureMessage(actual interface{}) string {
	return fmt.Sprintf(
		"At least one container should match: \n%s",
		matcher.executed.FailureMessage(&matcher.container),
	)
}

func (matcher *ContainerMatcher) NegatedFailureMessage(actual interface{}) string {
	return fmt.Sprintf(
		"No container should match: \n%s",
		matcher.executed.FailureMessage(&matcher.container),
	)
}
