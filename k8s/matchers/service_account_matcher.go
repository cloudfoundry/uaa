package matchers

import (
	"fmt"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	coreV1 "k8s.io/api/core/v1"
)

type ServiceAccountMatcher struct {
	meta   *ObjectMetaMatcher
	fields map[string]types.GomegaMatcher

	executed types.GomegaMatcher
}

func RepresentingServiceAccount() *ServiceAccountMatcher {
	return &ServiceAccountMatcher{NewObjectMetaMatcher(), map[string]types.GomegaMatcher{}, nil}
}

func (matcher *ServiceAccountMatcher) Match(actual interface{}) (bool, error) {
	serviceAccount, ok := actual.(*coreV1.ServiceAccount)
	if !ok {
		return false, fmt.Errorf("Expected a service account. Got\n%s", format.Object(actual, 1))
	}

	matcher.executed = matcher.meta
	if pass, err := matcher.meta.Match(serviceAccount.ObjectMeta); !pass || err != nil {
		return pass, err
	}

	matcher.executed = gstruct.MatchFields(gstruct.IgnoreExtras, matcher.fields)

	return matcher.executed.Match(*serviceAccount)
}

func (matcher *ServiceAccountMatcher) WithName(actual string) *ServiceAccountMatcher {
	matcher.meta.WithName(actual)
	return matcher
}

func (matcher *ServiceAccountMatcher) WithLabels(labels map[string]string) *ServiceAccountMatcher {
	matcher.meta.WithLabels(labels)

	return matcher
}

func (matcher *ServiceAccountMatcher) WithAutomountServiceAccountToken(value bool) *ServiceAccountMatcher {
	matcher.fields["AutomountServiceAccountToken"] = gomega.Equal(&value)

	return matcher
}

func (matcher *ServiceAccountMatcher) FailureMessage(actual interface{}) string {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *ServiceAccountMatcher) NegatedFailureMessage(actual interface{}) string {
	return matcher.executed.NegatedFailureMessage(actual)
}
