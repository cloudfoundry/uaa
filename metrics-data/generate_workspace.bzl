# The following dependencies were calculated from:
#
# generate_workspace --maven_project=/Users/jspawar/workspace/uaa/metrics-data --repositories=https://jcenter.bintray.com --repositories=https://repo.spring.io/plugins-release --repositories=https://plugins.gradle.org/m2/


def generated_maven_jars():
  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-metrics-data:jar:4.20.0-SNAPSHOT
  native.maven_jar(
      name = "com_fasterxml_jackson_core_jackson_databind",
      artifact = "com.fasterxml.jackson.core:jackson-databind:2.9.6",
      repository = "https://plugins.gradle.org/m2/",
      sha1 = "cfa4f316351a91bfd95cb0644c6a2c95f52db1fc",
  )


  # junit:junit:jar:4.12
  native.maven_jar(
      name = "org_hamcrest_hamcrest_core",
      artifact = "org.hamcrest:hamcrest-core:1.3",
      repository = "https://plugins.gradle.org/m2/",
      sha1 = "42a25dc3219429f0e5d060061f71acb49bf010a0",
  )


  # com.fasterxml.jackson.core:jackson-databind:bundle:2.9.6
  native.maven_jar(
      name = "com_fasterxml_jackson_core_jackson_core",
      artifact = "com.fasterxml.jackson.core:jackson-core:2.9.6",
      repository = "https://plugins.gradle.org/m2/",
      sha1 = "4e393793c37c77e042ccc7be5a914ae39251b365",
  )


  # org.cloudfoundry.identity:cloudfoundry-identity-metrics-data:jar:4.20.0-SNAPSHOT wanted version 2.9.6
  # com.fasterxml.jackson.core:jackson-databind:bundle:2.9.6
  # pom.xml wanted version 2.9.6
  native.maven_jar(
      name = "com_fasterxml_jackson_core_jackson_annotations",
      artifact = "com.fasterxml.jackson.core:jackson-annotations:2.9.0",
      repository = "https://plugins.gradle.org/m2/",
      sha1 = "07c10d545325e3a6e72e06381afe469fd40eb701",
  )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-metrics-data:jar:4.20.0-SNAPSHOT
  native.maven_jar(
      name = "junit_junit",
      artifact = "junit:junit:4.12",
      repository = "https://plugins.gradle.org/m2/",
      sha1 = "2973d150c0dc1fefe998f834810d68f278ea58ec",
  )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-metrics-data:jar:4.20.0-SNAPSHOT
  native.maven_jar(
      name = "org_hamcrest_hamcrest_all",
      artifact = "org.hamcrest:hamcrest-all:1.3",
      repository = "https://plugins.gradle.org/m2/",
      sha1 = "63a21ebc981131004ad02e0434e799fd7f3a8d5a",
  )




def generated_java_libraries():
  native.java_library(
      name = "com_fasterxml_jackson_core_jackson_databind",
      visibility = ["//visibility:public"],
      exports = ["@com_fasterxml_jackson_core_jackson_databind//jar"],
      runtime_deps = [
          ":com_fasterxml_jackson_core_jackson_annotations",
          ":com_fasterxml_jackson_core_jackson_core",
      ],
  )


  native.java_library(
      name = "org_hamcrest_hamcrest_core",
      visibility = ["//visibility:public"],
      exports = ["@org_hamcrest_hamcrest_core//jar"],
  )


  native.java_library(
      name = "com_fasterxml_jackson_core_jackson_core",
      visibility = ["//visibility:public"],
      exports = ["@com_fasterxml_jackson_core_jackson_core//jar"],
  )


  native.java_library(
      name = "com_fasterxml_jackson_core_jackson_annotations",
      visibility = ["//visibility:public"],
      exports = ["@com_fasterxml_jackson_core_jackson_annotations//jar"],
  )


  native.java_library(
      name = "junit_junit",
      visibility = ["//visibility:public"],
      exports = ["@junit_junit//jar"],
      runtime_deps = [
          ":org_hamcrest_hamcrest_core",
      ],
  )


  native.java_library(
      name = "org_hamcrest_hamcrest_all",
      visibility = ["//visibility:public"],
      exports = ["@org_hamcrest_hamcrest_all//jar"],
  )


