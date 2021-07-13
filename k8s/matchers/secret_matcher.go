package matchers

import (
	"fmt"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	coreV1 "k8s.io/api/core/v1"
)

type SecretMatcher struct {
	stringData types.GomegaMatcher
	data       types.GomegaMatcher
	meta       *ObjectMetaMatcher

	executed types.GomegaMatcher
}

func RepresentingASecret() *SecretMatcher {
	return &SecretMatcher{
		nil,
		nil,
		NewObjectMetaMatcher(),
		nil,
	}
}

func (matcher *SecretMatcher) WithStringData(name string, value string) *SecretMatcher {
	matcher.stringData = MatchKeys(IgnoreExtras, Keys{
		name: Equal(value),
	})
	return matcher
}

func (matcher *SecretMatcher) WithData(name string, value []byte) *SecretMatcher {
	matcher.data = MatchKeys(IgnoreExtras, Keys{
		name: Equal(value),
	})
	return matcher
}

func (matcher *SecretMatcher) WithName(name string) *SecretMatcher {
	matcher.meta.WithName(name)

	return matcher
}

func (matcher *SecretMatcher) Match(actual interface{}) (success bool, err error) {
	secret, ok := actual.(*coreV1.Secret)
	if !ok {
		return false, fmt.Errorf("Expected a secret. Got\n%s", format.Object(actual, 1))
	}

	if matcher.stringData != nil {
		matcher.executed = matcher.stringData
		if pass, err := matcher.stringData.Match(secret.StringData); !pass || err != nil {
			return pass, err
		}
	}

	if matcher.data != nil {
		matcher.executed = matcher.data
		if pass, err := matcher.data.Match(secret.Data); !pass || err != nil {
			return pass, err
		}
	}

	matcher.executed = matcher.meta
	if pass, err := matcher.meta.Match(secret.ObjectMeta); !pass || err != nil {
		return pass, err
	}

	return true, nil
}

func (matcher *SecretMatcher) FailureMessage(actual interface{}) string {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *SecretMatcher) NegatedFailureMessage(actual interface{}) string {
	return matcher.executed.NegatedFailureMessage(actual)
}
