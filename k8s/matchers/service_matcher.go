package matchers

import (
	"fmt"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	coreV1 "k8s.io/api/core/v1"
)

type ServiceMatcher struct {
	meta *ObjectMetaMatcher

	executed types.GomegaMatcher
}

func RepresentingService() *ServiceMatcher {
	return &ServiceMatcher{NewObjectMetaMatcher(), nil}
}

func (matcher *ServiceMatcher) WithLabels(labels map[string]string) *ServiceMatcher {
	matcher.meta.WithLabels(labels)

	return matcher
}

func (matcher *ServiceMatcher) WithNamespace(namespace string) *ServiceMatcher {
	matcher.meta.WithNamespace(namespace)

	return matcher
}

func (matcher *ServiceMatcher) Match(actual interface{}) (bool, error) {
	service, ok := actual.(*coreV1.Service)
	if !ok {
		return false, fmt.Errorf("Expected a service. Got\n%s", format.Object(actual, 1))
	}

	matcher.executed = matcher.meta
	if pass, err := matcher.meta.Match(service.ObjectMeta); !pass || err != nil {
		return pass, err
	}

	return true, nil
}

func (matcher *ServiceMatcher) FailureMessage(actual interface{}) string {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *ServiceMatcher) NegatedFailureMessage(actual interface{}) string {
	return matcher.executed.NegatedFailureMessage(actual)
}
