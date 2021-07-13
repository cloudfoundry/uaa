package matchers

import (
	"fmt"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ObjectMetaMatcherConfig func(*ObjectMetaMatcher)

type ObjectMetaMatcher struct {
	fields map[string]types.GomegaMatcher

	meta     *metaV1.ObjectMeta
	executed types.GomegaMatcher
}

func NewObjectMetaMatcher() *ObjectMetaMatcher {
	return &ObjectMetaMatcher{map[string]types.GomegaMatcher{}, nil, nil}
}

func (matcher *ObjectMetaMatcher) WithName(name string) *ObjectMetaMatcher {
	matcher.fields["Name"] = gomega.Equal(name)

	return matcher
}

func (matcher *ObjectMetaMatcher) WithLabels(labels map[string]string) *ObjectMetaMatcher {
	var matchers []types.GomegaMatcher
	for label, value := range labels {
		matchers = append(matchers, gomega.HaveKeyWithValue(label, value))
	}

	matcher.fields["Labels"] = gomega.SatisfyAll(matchers...)
	return matcher
}

func (matcher *ObjectMetaMatcher) WithNamespace(namespace string) *ObjectMetaMatcher {
	matcher.fields["Namespace"] = gomega.Equal(namespace)
	return matcher
}

func (matcher *ObjectMetaMatcher) WithAnnotations(annotations map[string]string) *ObjectMetaMatcher {
	var matchers []types.GomegaMatcher
	for annotation, value := range annotations {
		matchers = append(matchers, gomega.HaveKeyWithValue(annotation, value))
	}

	matcher.fields["Annotations"] = gomega.SatisfyAll(matchers...)
	return matcher
}

func (matcher *ObjectMetaMatcher) Match(actual interface{}) (bool, error) {
	meta, ok := actual.(metaV1.ObjectMeta)
	if !ok {
		return false, fmt.Errorf("Expecting meta.ObjectMeta. Got\n%s", format.Object(actual, 1))
	}

	matcher.meta = &meta
	matcher.executed = gstruct.MatchFields(gstruct.IgnoreExtras, matcher.fields)
	return matcher.executed.Match(meta)
}

func (matcher *ObjectMetaMatcher) FailureMessage(actual interface{}) string {
	return fmt.Sprintf(
		"ObjectMeta should match: \n%s",
		matcher.executed.FailureMessage(&matcher.meta),
	)
}

func (matcher *ObjectMetaMatcher) NegatedFailureMessage(actual interface{}) string {
	return fmt.Sprintf(
		"ObjectMeta should not match: \n%s",
		matcher.executed.FailureMessage(&matcher.meta),
	)
}
