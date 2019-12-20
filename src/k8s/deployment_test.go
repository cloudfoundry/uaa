package deployment_test

import (
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	"k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"os/exec"
)

var _ = Describe("Deployment", func() {
	It("Sets the image sha for the UAA container", func() {
		command := exec.Command("ytt", "-f", "./templates/deployment.yml", "-f", "./templates/values/values.yml")
		session, err := gexec.Start(command, GinkgoWriter, GinkgoWriter)
		Expect(err).NotTo(HaveOccurred())
		Eventually(session).Should(gexec.Exit())

		stdOut := session.Wait().Out.Contents()
		decode := scheme.Codecs.UniversalDeserializer().Decode
		obj, _, err := decode(stdOut, nil, nil)
		if err != nil {
			fmt.Printf("%#v", err)
		}
		deployment := obj.(*v1.Deployment)

		Expect(deployment.Spec.Template.Spec.Containers[0].Image).To(Equal("cfidentity/uaa@sha256:93b70b26fbb3de88d93728b0daf1ea7b001fde89a24e283c3db36bf4c6af087c"))
	})
})
