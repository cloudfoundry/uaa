package k8s_test

import (
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"

	"gopkg.in/yaml.v2"
)

const UaaYmlConfigKey = "uaa.yml"

type UaaYmlMatcher struct {
	fields       map[string]types.GomegaMatcher
	configFields gstruct.Fields
	executed     types.GomegaMatcher
}

func NewUaaYmlMatcher() *UaaYmlMatcher {
	return &UaaYmlMatcher{
		fields:       map[string]types.GomegaMatcher{},
		configFields: gstruct.Fields{},
		executed:     nil,
	}
}

func (matcher *UaaYmlMatcher) WithFields(fields gstruct.Fields) *UaaYmlMatcher {
	matcher.configFields = fields
	return matcher
}

func (matcher *UaaYmlMatcher) Match(actual interface{}) (success bool, err error) {
	configMapData, ok := actual.(map[string]string)
	if !ok {
		panic("expected a map[string]string")
	}

	uaaYml := UaaConfig{}
	err = yaml.Unmarshal([]byte(configMapData[UaaYmlConfigKey]), &uaaYml)
	if err != nil {
		panic("Failed to unmarshal")
	}

	matcher.executed = gstruct.MatchFields(gstruct.IgnoreExtras, matcher.configFields)
	return matcher.executed.Match(uaaYml)
}

func (matcher *UaaYmlMatcher) FailureMessage(actual interface{}) (message string) {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *UaaYmlMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return matcher.executed.NegatedFailureMessage(actual)
}
