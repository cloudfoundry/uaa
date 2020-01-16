package k8s_test

import (
	"fmt"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	v1 "k8s.io/api/core/v1"
)

type DataMatcherConfig func(*UaaYmlMatcher)

type ConfigMapMatcher struct {
	dataMatcher *UaaYmlMatcher

	executed types.GomegaMatcher
}


func RepresentingConfigMap() *ConfigMapMatcher {
	return &ConfigMapMatcher{NewUaaYmlMatcher(), nil}
}

func (matcher *ConfigMapMatcher) WithDataMatching(config DataMatcherConfig) *ConfigMapMatcher {
	config(matcher.dataMatcher)

	return matcher
}

func (matcher *ConfigMapMatcher) Match(actual interface{}) (success bool, err error) {
	configMap, ok := actual.(*v1.ConfigMap)
	if !ok {
		return false, fmt.Errorf("Expected a ConfigMap. Got\n%s", format.Object(actual, 1))
	}

	matcher.executed = matcher.dataMatcher
	pass, err := matcher.dataMatcher.Match(configMap.Data)
	if !pass || err != nil {
		return pass, err
	}

	return true, nil
}

func (matcher *ConfigMapMatcher) FailureMessage(actual interface{}) (message string) {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *ConfigMapMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return matcher.executed.NegatedFailureMessage(actual)
}
