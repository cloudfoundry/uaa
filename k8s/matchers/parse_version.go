package matchers

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
)

type version struct {
	Version string `yaml:version`
}

func LoadVersionFromValues() string {
	content, err := ioutil.ReadFile("../templates/values/version.yml")

	if err != nil {
		log.Fatal(err)
	}

	v := version{}
	err = yaml.Unmarshal(content, &v)
	if err != nil {
		log.Fatalln(err)
	}

	return v.Version

}
