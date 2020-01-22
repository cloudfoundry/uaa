package k8s_test

import (
	"fmt"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	v1 "k8s.io/api/core/v1"
)

type DataMatcherConfig func(*DataFieldMatcher)

type ConfigMapMatcher struct {
	dataFields map[string]types.GomegaMatcher

	executed types.GomegaMatcher
}

func RepresentingConfigMap() *ConfigMapMatcher {
	return &ConfigMapMatcher{map[string]types.GomegaMatcher{}, nil}
}

func (matcher *ConfigMapMatcher) WithDataFieldMatching(fieldName string, config DataMatcherConfig) *ConfigMapMatcher {
	dataField := NewDataFieldMatcher(fieldName)
	config(dataField)
	matcher.dataFields[fieldName] = dataField

	return matcher
}

func (matcher *ConfigMapMatcher) Match(actual interface{}) (success bool, err error) {
	configMap, ok := actual.(*v1.ConfigMap)
	if !ok {
		return false, fmt.Errorf("Expected a ConfigMap. Got\n%s", format.Object(actual, 1))
	}

	for k, v := range matcher.dataFields {
		data := configMap.Data[k]
		matcher.executed = v

		pass, err := v.Match(data)
		if !pass || err != nil {
			return pass, err
		}
	}

	return true, nil
}

func (matcher *ConfigMapMatcher) FailureMessage(actual interface{}) (message string) {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *ConfigMapMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return matcher.executed.NegatedFailureMessage(actual)
}
