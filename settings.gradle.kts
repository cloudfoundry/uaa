rootProject.name = "cloudfoundry-identity-parent"
include(":cloudfoundry-identity-metrics-data")
include(":cloudfoundry-identity-model")
include(":cloudfoundry-identity-server")
include(":cloudfoundry-identity-statsd")
include(":cloudfoundry-identity-statsd-lib")
include(":cloudfoundry-identity-uaa")

project(":cloudfoundry-identity-metrics-data").projectDir = file("metrics-data")
project(":cloudfoundry-identity-model").projectDir = file("model")
project(":cloudfoundry-identity-server").projectDir = file("server")
project(":cloudfoundry-identity-uaa").projectDir = file("uaa")
project(":cloudfoundry-identity-statsd").projectDir = file("statsd")
project(":cloudfoundry-identity-statsd-lib").projectDir = file("statsd-lib")