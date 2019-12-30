package k8s_test

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var templateBasePath string

func init() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("Could not initialize k8s_test package: can't find location of this file")
	}

	relative := filepath.Join(filepath.Dir(filename), "..", "templates")
	abs, err := filepath.Abs(relative)
	if err != nil {
		panic(fmt.Sprintf("Could not initialize k8s_test package: %v", err))
	}

	templateBasePath = abs
}

func pathToTemplate(name string) string {
	return filepath.Join(templateBasePath, name)
}

func pathToTestOverlay(name string) string {
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		panic(fmt.Sprintf("Could not load fixture from testdata: %v", err))
	}

	return abs
}

func TestDeployment(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Deployment Suite")
}
