package matchers

import (
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

type DataValueMatcher struct {
	fieldName string
	field     types.GomegaMatcher
	dataValue string
}

func NewDataValueMatcher(fieldName string) *DataValueMatcher {
	return &DataValueMatcher{
		fieldName: fieldName,
		field:     nil,
	}
}

func (matcher *DataValueMatcher) WithValue(field string) *DataValueMatcher {
	matcher.field = gomega.Equal(field)
	return matcher
}

func (matcher *DataValueMatcher) Match(actual interface{}) (success bool, err error) {
	matcher.dataValue = actual.(string)

	return matcher.field.Match(matcher.dataValue)
}

func (matcher *DataValueMatcher) FailureMessage(actual interface{}) (message string) {
	return matcher.field.FailureMessage(&matcher.dataValue)
}

func (matcher *DataValueMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return matcher.field.NegatedFailureMessage(&matcher.dataValue)
}
