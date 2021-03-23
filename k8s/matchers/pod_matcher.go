package matchers

import (
	"fmt"
	"github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	coreV1 "k8s.io/api/core/v1"
)

type PodMatcherConfig func(*PodMatcher)

type PodMatcher struct {
	containers     []types.GomegaMatcher
	meta           *ObjectMetaMatcher
	serviceAccount types.GomegaMatcher
	volumes        map[string]types.GomegaMatcher

	executed types.GomegaMatcher
}

func NewPodMatcher() *PodMatcher {
	return &PodMatcher{
		[]types.GomegaMatcher{},
		NewObjectMetaMatcher(),
		nil,
		map[string]types.GomegaMatcher{},
		nil,
	}
}

func (matcher *PodMatcher) WithContainerMatching(config ContainerMatcherConfig) *PodMatcher {
	container := NewContainerMatcher()
	config(container)
	matcher.containers = append(matcher.containers, container)

	return matcher
}

func (matcher *PodMatcher) WithServiceAccountMatching(serviceAccount string) *PodMatcher {
	matcher.serviceAccount = gomega.Equal(serviceAccount)

	return matcher
}

func (matcher *PodMatcher) WithMetaMatching(config ObjectMetaMatcherConfig) *PodMatcher {
	config(matcher.meta)

	return matcher
}

func (matcher *PodMatcher) WithVolume(name string, volumeMatcher types.GomegaMatcher) *PodMatcher {
	matcher.volumes[name] = volumeMatcher

	return matcher
}

func (matcher *PodMatcher) Match(actual interface{}) (bool, error) {
	pod, ok := actual.(coreV1.PodTemplateSpec)
	if !ok {
		return false, fmt.Errorf("Expected pod. Got\n%s", format.Object(actual, 1))
	}

	if matcher.serviceAccount != nil {
		matcher.executed = gomega.Equal(matcher.serviceAccount)
		if pass, err := matcher.serviceAccount.Match(pod.Spec.ServiceAccountName); !pass || err != nil {
			return pass, err
		}
	}

	for _, container := range matcher.containers {
		contains := gomega.ContainElement(container)

		matcher.executed = container
		if pass, err := contains.Match(pod.Spec.Containers); !pass || err != nil {
			return pass, err
		}
	}

	matcher.executed = matcher.meta
	if pass, err := matcher.meta.Match(pod.ObjectMeta); !pass || err != nil {
		return pass, err
	}

	identifyVolumeByName := func(element interface{}) string {
		return element.(coreV1.Volume).Name
	}
	matcher.executed = gstruct.MatchElements(identifyVolumeByName, gstruct.IgnoreExtras, matcher.volumes)
	if pass, err := matcher.executed.Match(pod.Spec.Volumes); !pass || err != nil {
		return pass, err
	}

	return true, nil
}

func (matcher *PodMatcher) FailureMessage(actual interface{}) string {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *PodMatcher) NegatedFailureMessage(actual interface{}) string {
	return matcher.executed.NegatedFailureMessage(actual)
}
