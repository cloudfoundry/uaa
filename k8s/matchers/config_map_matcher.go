package matchers

import (
	"fmt"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	v1 "k8s.io/api/core/v1"
)

type DataFieldMatcherConfig func(*DataFieldMatcher)
type DataValueMatcherConfig func(*DataValueMatcher)

type ConfigMapMatcher struct {
	dataFields map[string]types.GomegaMatcher
	meta       *ObjectMetaMatcher

	executed types.GomegaMatcher
}

func RepresentingConfigMap() *ConfigMapMatcher {
	return &ConfigMapMatcher{map[string]types.GomegaMatcher{}, NewObjectMetaMatcher(), nil}
}

func (matcher *ConfigMapMatcher) WithDataFieldMatching(fieldName string, config DataFieldMatcherConfig) *ConfigMapMatcher {
	dataField := NewDataFieldMatcher(fieldName)
	config(dataField)
	matcher.dataFields[fieldName] = dataField

	return matcher
}

func (matcher *ConfigMapMatcher) WithDataValueMatching(fieldName string, config DataValueMatcherConfig) *ConfigMapMatcher {
	dataField := NewDataValueMatcher(fieldName)
	config(dataField)
	matcher.dataFields[fieldName] = dataField
	return matcher
}

func (matcher *ConfigMapMatcher) WithLabels(labels map[string]string) *ConfigMapMatcher {
	matcher.meta.WithLabels(labels)

	return matcher
}

func (matcher *ConfigMapMatcher) WithNamespace(namespace string) *ConfigMapMatcher {
	matcher.meta.WithNamespace(namespace)

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

	matcher.executed = matcher.meta
	if pass, err := matcher.meta.Match(configMap.ObjectMeta); !pass || err != nil {
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
