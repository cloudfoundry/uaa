package matchers

import (
	"fmt"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	appV1 "k8s.io/api/apps/v1"
)

type DeploymentMatcher struct {
	pod  *PodMatcher
	meta *ObjectMetaMatcher

	executed types.GomegaMatcher
}

func RepresentingDeployment() *DeploymentMatcher {
	return &DeploymentMatcher{
		NewPodMatcher(),
		NewObjectMetaMatcher(),
		nil,
	}
}

func (matcher *DeploymentMatcher) WithPodMatching(config PodMatcherConfig) *DeploymentMatcher {
	config(matcher.pod)

	return matcher
}

func (matcher *DeploymentMatcher) WithMetaMatching(config ObjectMetaMatcherConfig) *DeploymentMatcher {
	config(matcher.meta)

	return matcher
}

func (matcher *DeploymentMatcher) Match(actual interface{}) (bool, error) {
	deployment, ok := actual.(*appV1.Deployment)
	if !ok {
		return false, fmt.Errorf("Expected a deployment. Got\n%s", format.Object(actual, 1))
	}

	matcher.executed = matcher.pod // so we can have good pod-specific failure messages
	if pass, err := matcher.pod.Match(deployment.Spec.Template); !pass || err != nil {
		return pass, err
	}

	matcher.executed = matcher.meta
	if pass, err := matcher.meta.Match(deployment.ObjectMeta); !pass || err != nil {
		return pass, err
	}

	return true, nil
}

func (matcher *DeploymentMatcher) FailureMessage(actual interface{}) string {
	return matcher.executed.FailureMessage(actual)
}

func (matcher *DeploymentMatcher) NegatedFailureMessage(actual interface{}) string {
	return matcher.executed.NegatedFailureMessage(actual)
}
