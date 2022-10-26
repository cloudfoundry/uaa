package matchers

import (
	"fmt"
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"

	"gopkg.in/yaml.v3"
)

type DataFieldMatcher struct {
	fieldName    string
	fields       map[string]types.GomegaMatcher
	configFields gstruct.Fields
	executed     types.GomegaMatcher
}

func NewDataFieldMatcher(fieldName string) *DataFieldMatcher {
	return &DataFieldMatcher{
		fieldName:    fieldName,
		fields:       map[string]types.GomegaMatcher{},
		configFields: gstruct.Fields{},
		executed:     nil,
	}
}

func (matcher *DataFieldMatcher) WithFields(fields gstruct.Fields) *DataFieldMatcher {
	matcher.configFields = fields
	return matcher
}

func (matcher *DataFieldMatcher) Match(actual interface{}) (success bool, err error) {
	configMapData, ok := actual.(string)
	if !ok {
		panic(fmt.Sprintf("expected data field %s to have type string", matcher.fieldName))
	}

	uaaYml := UaaConfig{} // TODO: unmarshal data fields into arbitrary data types, not just UaaConfig
	err = yaml.Unmarshal([]byte(configMapData), &uaaYml)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal: %v", err))
	}

	matcher.executed = gstruct.MatchFields(gstruct.IgnoreExtras, matcher.configFields)
	return matcher.executed.Match(uaaYml)
}

func (matcher *DataFieldMatcher) FailureMessage(actual interface{}) (message string) {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *DataFieldMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return matcher.executed.NegatedFailureMessage(actual)
}
