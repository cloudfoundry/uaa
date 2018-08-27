# The following dependencies were calculated from:
#
# generate_workspace --maven_project=/Users/jspawar/workspace/uaa/model --repositories=https://jcenter.bintray.com --repositories=https://repo.spring.io/plugins-release --repositories=https://plugins.gradle.org/m2/


def generated_maven_jars():
  excludes = native.existing_rules().keys()

  # org.springframework:spring-core:jar:4.3.18.RELEASE
  if "commons_logging_commons_logging" not in excludes:
    native.maven_jar(
        name = "commons_logging_commons_logging",
        artifact = "commons-logging:commons-logging:1.2",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "4bfc12adfe4842bf07b657f0369c4cb522955686",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  if "org_slf4j_slf4j_api" not in excludes:
    native.maven_jar(
        name = "org_slf4j_slf4j_api",
        artifact = "org.slf4j:slf4j-api:1.7.25",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "da76ca59f6a57ee3102f8f9bd9cee742973efa8a",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  if "javax_validation_validation_api" not in excludes:
    native.maven_jar(
        name = "javax_validation_validation_api",
        artifact = "javax.validation:validation-api:2.0.1.Final",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "cb855558e6271b1b32e716d24cb85c7f583ce09e",
    )


  # org.springframework.security:spring-security-config:jar:4.2.7.RELEASE
  # org.springframework.security:spring-security-core:jar:4.2.7.RELEASE got requested version
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE got requested version
  if "aopalliance_aopalliance" not in excludes:
    native.maven_jar(
        name = "aopalliance_aopalliance",
        artifact = "aopalliance:aopalliance:1.0",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "0235ba8b489512805ac13a8f9ea77a1ca5ebe3e8",
    )


  # org.springframework.security:spring-security-core:jar:4.2.7.RELEASE got requested version
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE wanted version 3.2.18.RELEASE
  # org.springframework:spring-web:jar:4.3.18.RELEASE
  # org.springframework:spring-webmvc:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-config:jar:4.2.7.RELEASE got requested version
  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE wanted version 4.0.9.RELEASE
  if "org_springframework_spring_context" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_context",
        artifact = "org.springframework:spring-context:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "d302953b509e6d380856e245bf80c29770c08c98",
    )


  # junit:junit:jar:4.12
  if "org_hamcrest_hamcrest_core" not in excludes:
    native.maven_jar(
        name = "org_hamcrest_hamcrest_core",
        artifact = "org.hamcrest:hamcrest-core:1.3",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "42a25dc3219429f0e5d060061f71acb49bf010a0",
    )


  # org.springframework:spring-context:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-core:jar:4.2.7.RELEASE got requested version
  # org.springframework:spring-web:jar:4.3.18.RELEASE
  # org.springframework:spring-webmvc:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-config:jar:4.2.7.RELEASE got requested version
  if "org_springframework_spring_aop" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_aop",
        artifact = "org.springframework:spring-aop:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "dd930265a504563d76de79864ae3196f6e9035e0",
    )


  # org.springframework.security:spring-security-core:jar:4.2.7.RELEASE got requested version
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE wanted version 3.2.18.RELEASE
  # org.springframework:spring-context:jar:4.3.18.RELEASE
  # org.springframework:spring-webmvc:jar:4.3.18.RELEASE got requested version
  if "org_springframework_spring_expression" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_expression",
        artifact = "org.springframework:spring-expression:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "64f2270bfd9d615c8c3b9d94995867f39391ed30",
    )


  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE
  if "commons_codec_commons_codec" not in excludes:
    native.maven_jar(
        name = "commons_codec_commons_codec",
        artifact = "commons-codec:commons-codec:1.9",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "9ce04e34240f674bc72680f8b843b1457383161a",
    )


  # org.codehaus.jackson:jackson-mapper-asl:jar:1.9.13
  if "org_codehaus_jackson_jackson_core_asl" not in excludes:
    native.maven_jar(
        name = "org_codehaus_jackson_jackson_core_asl",
        artifact = "org.codehaus.jackson:jackson-core-asl:1.9.13",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "3c304d70f42f832e0a86d45bd437f692129299a4",
    )


  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE
  if "org_springframework_security_spring_security_web" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_web",
        artifact = "org.springframework.security:spring-security-web:3.2.10.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "b925996ca5a7310e3315705cd2b69a15214ee3e1",
    )


  # org.springframework.security:spring-security-config:jar:4.2.7.RELEASE
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE wanted version 3.2.10.RELEASE
  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE wanted version 3.2.10.RELEASE
  if "org_springframework_security_spring_security_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_core",
        artifact = "org.springframework.security:spring-security-core:4.2.7.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "3b74ac31cb84d1cab6dcc55887391dfe593a30f6",
    )


  # pom.xml got requested version
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE wanted version 3.2.18.RELEASE
  # org.springframework:spring-webmvc:jar:4.3.18.RELEASE got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  if "org_springframework_spring_web" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_web",
        artifact = "org.springframework:spring-web:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "e41042a70a7d80da52261c1dfc569c7518b70dce",
    )


  # org.springframework:spring-aop:jar:4.3.18.RELEASE
  # org.springframework:spring-context:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-core:jar:4.2.7.RELEASE got requested version
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE wanted version 3.2.18.RELEASE
  # org.springframework:spring-webmvc:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-config:jar:4.2.7.RELEASE got requested version
  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE wanted version 4.0.9.RELEASE
  # org.springframework:spring-web:jar:4.3.18.RELEASE got requested version
  if "org_springframework_spring_beans" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_beans",
        artifact = "org.springframework:spring-beans:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "27460686b16b3ffee60bb3365cd56bba6ed860ff",
    )


  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE
  if "org_codehaus_jackson_jackson_mapper_asl" not in excludes:
    native.maven_jar(
        name = "org_codehaus_jackson_jackson_mapper_asl",
        artifact = "org.codehaus.jackson:jackson-mapper-asl:1.9.13",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "1ee2f2bed0e5dd29d1cb155a166e6f8d50bbddb7",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE wanted version 4.0.9.RELEASE
  if "org_springframework_spring_webmvc" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_webmvc",
        artifact = "org.springframework:spring-webmvc:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "067ad7f59830df97ab73f8c7ab53ea33ae7dcb68",
    )


  # org.springframework:spring-context:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-core:jar:4.2.7.RELEASE got requested version
  # org.springframework.security:spring-security-web:jar:3.2.10.RELEASE wanted version 3.2.18.RELEASE
  # org.springframework:spring-webmvc:jar:4.3.18.RELEASE got requested version
  # org.springframework.security:spring-security-config:jar:4.2.7.RELEASE got requested version
  # org.springframework:spring-aop:jar:4.3.18.RELEASE got requested version
  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE wanted version 4.0.9.RELEASE
  # org.springframework:spring-expression:jar:4.3.18.RELEASE got requested version
  # org.springframework:spring-beans:jar:4.3.18.RELEASE
  # org.springframework:spring-web:jar:4.3.18.RELEASE got requested version
  if "org_springframework_spring_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_core",
        artifact = "org.springframework:spring-core:4.3.18.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "4acbce682c3dfe38181d57b7e0792e2cc21e4f77",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  # org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE wanted version 3.2.10.RELEASE
  if "org_springframework_security_spring_security_config" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_config",
        artifact = "org.springframework.security:spring-security-config:4.2.7.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "5c096aa25285e3f8169b44c7dcf76166809921b1",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  if "junit_junit" not in excludes:
    native.maven_jar(
        name = "junit_junit",
        artifact = "junit:junit:4.12",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "2973d150c0dc1fefe998f834810d68f278ea58ec",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  if "org_hamcrest_hamcrest_all" not in excludes:
    native.maven_jar(
        name = "org_hamcrest_hamcrest_all",
        artifact = "org.hamcrest:hamcrest-all:1.3",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "63a21ebc981131004ad02e0434e799fd7f3a8d5a",
    )


  # pom.xml got requested version
  # org.cloudfoundry.identity:cloudfoundry-identity-model:jar:4.20.0-SNAPSHOT
  if "org_springframework_security_oauth_spring_security_oauth2" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_oauth_spring_security_oauth2",
        artifact = "org.springframework.security.oauth:spring-security-oauth2:2.0.15.RELEASE",
        repository = "https://plugins.gradle.org/m2/",
        sha1 = "791b7060abe9172bd29033c321f6d455e299e48f",
    )




def generated_java_libraries():
  excludes = native.existing_rules().keys()

  if "commons_logging_commons_logging" not in excludes:
    native.java_library(
        name = "commons_logging_commons_logging",
        visibility = ["//visibility:public"],
        exports = ["@commons_logging_commons_logging//jar"],
    )


  if "org_slf4j_slf4j_api" not in excludes:
    native.java_library(
        name = "org_slf4j_slf4j_api",
        visibility = ["//visibility:public"],
        exports = ["@org_slf4j_slf4j_api//jar"],
    )


  if "javax_validation_validation_api" not in excludes:
    native.java_library(
        name = "javax_validation_validation_api",
        visibility = ["//visibility:public"],
        exports = ["@javax_validation_validation_api//jar"],
    )


  if "aopalliance_aopalliance" not in excludes:
    native.java_library(
        name = "aopalliance_aopalliance",
        visibility = ["//visibility:public"],
        exports = ["@aopalliance_aopalliance//jar"],
    )


  if "org_springframework_spring_context" not in excludes:
    native.java_library(
        name = "org_springframework_spring_context",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_context//jar"],
        runtime_deps = [
            ":org_springframework_spring_aop",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
        ],
    )


  if "org_hamcrest_hamcrest_core" not in excludes:
    native.java_library(
        name = "org_hamcrest_hamcrest_core",
        visibility = ["//visibility:public"],
        exports = ["@org_hamcrest_hamcrest_core//jar"],
    )


  if "org_springframework_spring_aop" not in excludes:
    native.java_library(
        name = "org_springframework_spring_aop",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_aop//jar"],
        runtime_deps = [
            ":commons_logging_commons_logging",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_core",
        ],
    )


  if "org_springframework_spring_expression" not in excludes:
    native.java_library(
        name = "org_springframework_spring_expression",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_expression//jar"],
        runtime_deps = [
            ":org_springframework_spring_core",
        ],
    )


  if "commons_codec_commons_codec" not in excludes:
    native.java_library(
        name = "commons_codec_commons_codec",
        visibility = ["//visibility:public"],
        exports = ["@commons_codec_commons_codec//jar"],
    )


  if "org_codehaus_jackson_jackson_core_asl" not in excludes:
    native.java_library(
        name = "org_codehaus_jackson_jackson_core_asl",
        visibility = ["//visibility:public"],
        exports = ["@org_codehaus_jackson_jackson_core_asl//jar"],
    )


  if "org_springframework_security_spring_security_web" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_web",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_web//jar"],
        runtime_deps = [
            ":aopalliance_aopalliance",
            ":org_springframework_security_spring_security_core",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
            ":org_springframework_spring_web",
        ],
    )


  if "org_springframework_security_spring_security_core" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_core//jar"],
        runtime_deps = [
            ":aopalliance_aopalliance",
            ":org_springframework_spring_aop",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
        ],
    )


  if "org_springframework_spring_web" not in excludes:
    native.java_library(
        name = "org_springframework_spring_web",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_web//jar"],
        runtime_deps = [
            ":commons_logging_commons_logging",
            ":org_springframework_spring_aop",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
        ],
    )


  if "org_springframework_spring_beans" not in excludes:
    native.java_library(
        name = "org_springframework_spring_beans",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_beans//jar"],
        runtime_deps = [
            ":commons_logging_commons_logging",
            ":org_springframework_spring_core",
        ],
    )


  if "org_codehaus_jackson_jackson_mapper_asl" not in excludes:
    native.java_library(
        name = "org_codehaus_jackson_jackson_mapper_asl",
        visibility = ["//visibility:public"],
        exports = ["@org_codehaus_jackson_jackson_mapper_asl//jar"],
        runtime_deps = [
            ":org_codehaus_jackson_jackson_core_asl",
        ],
    )


  if "org_springframework_spring_webmvc" not in excludes:
    native.java_library(
        name = "org_springframework_spring_webmvc",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_webmvc//jar"],
        runtime_deps = [
            ":org_springframework_spring_aop",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
            ":org_springframework_spring_web",
        ],
    )


  if "org_springframework_spring_core" not in excludes:
    native.java_library(
        name = "org_springframework_spring_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_core//jar"],
        runtime_deps = [
            ":commons_logging_commons_logging",
        ],
    )


  if "org_springframework_security_spring_security_config" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_config",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_config//jar"],
        runtime_deps = [
            ":aopalliance_aopalliance",
            ":org_springframework_security_spring_security_core",
            ":org_springframework_spring_aop",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
        ],
    )


  if "junit_junit" not in excludes:
    native.java_library(
        name = "junit_junit",
        visibility = ["//visibility:public"],
        exports = ["@junit_junit//jar"],
        runtime_deps = [
            ":org_hamcrest_hamcrest_core",
        ],
    )


  if "org_hamcrest_hamcrest_all" not in excludes:
    native.java_library(
        name = "org_hamcrest_hamcrest_all",
        visibility = ["//visibility:public"],
        exports = ["@org_hamcrest_hamcrest_all//jar"],
    )


  if "org_springframework_security_oauth_spring_security_oauth2" not in excludes:
    native.java_library(
        name = "org_springframework_security_oauth_spring_security_oauth2",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_oauth_spring_security_oauth2//jar"],
        runtime_deps = [
            ":aopalliance_aopalliance",
            ":commons_codec_commons_codec",
            ":org_codehaus_jackson_jackson_core_asl",
            ":org_codehaus_jackson_jackson_mapper_asl",
            ":org_springframework_security_spring_security_config",
            ":org_springframework_security_spring_security_core",
            ":org_springframework_security_spring_security_web",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
            ":org_springframework_spring_expression",
            ":org_springframework_spring_web",
            ":org_springframework_spring_webmvc",
        ],
    )


