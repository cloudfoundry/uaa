def generated_maven_jars():
  excludes = native.existing_rules().keys()

  if "javax_validation_validation_api" not in excludes:
    native.maven_jar(
        name = "javax_validation_validation_api",
        artifact = "javax.validation:validation-api:jar:2.0.1.Final",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_web" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_web",
        artifact = "org.springframework:spring-web:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_aop" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_aop",
        artifact = "org.springframework:spring-aop:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_beans" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_beans",
        artifact = "org.springframework:spring-beans:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_context" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_context",
        artifact = "org.springframework:spring-context:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_core",
        artifact = "org.springframework:spring-core:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_logging_commons_logging" not in excludes:
    native.maven_jar(
        name = "commons_logging_commons_logging",
        artifact = "commons-logging:commons-logging:jar:1.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_webmvc" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_webmvc",
        artifact = "org.springframework:spring-webmvc:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_expression" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_expression",
        artifact = "org.springframework:spring-expression:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_config" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_config",
        artifact = "org.springframework.security:spring-security-config:jar:4.2.7.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "aopalliance_aopalliance" not in excludes:
    native.maven_jar(
        name = "aopalliance_aopalliance",
        artifact = "aopalliance:aopalliance:jar:1.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_core",
        artifact = "org.springframework.security:spring-security-core:jar:4.2.7.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_oauth_spring_security_oauth2" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_oauth_spring_security_oauth2",
        artifact = "org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_codec_commons_codec" not in excludes:
    native.maven_jar(
        name = "commons_codec_commons_codec",
        artifact = "commons-codec:commons-codec:jar:1.9",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_slf4j_slf4j_api" not in excludes:
    native.maven_jar(
        name = "org_slf4j_slf4j_api",
        artifact = "org.slf4j:slf4j-api:jar:1.7.25",
        repository = "https://repo1.maven.org/maven2/",
    )

def generated_java_libraries():
  excludes = native.existing_rules().keys()

  if "javax_validation_validation_api" not in excludes:
    native.java_library(
        name = "javax_validation_validation_api",
        visibility = ["//visibility:public"],
        exports = ["@javax_validation_validation_api//jar"],
    )

  if "org_springframework_spring_web" not in excludes:
    native.java_library(
        name = "org_springframework_spring_web",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_web//jar"],
        runtime_deps = [
            ":org_springframework_spring_aop",
            ":org_springframework_spring_beans",
            ":org_springframework_spring_context",
            ":org_springframework_spring_core",
        ],
    )

  if "org_springframework_spring_aop" not in excludes:
    native.java_library(
        name = "org_springframework_spring_aop",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_aop//jar"],
    )

  if "org_springframework_spring_beans" not in excludes:
    native.java_library(
        name = "org_springframework_spring_beans",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_beans//jar"],
    )

  if "org_springframework_spring_context" not in excludes:
    native.java_library(
        name = "org_springframework_spring_context",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_context//jar"],
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

  if "commons_logging_commons_logging" not in excludes:
    native.java_library(
        name = "commons_logging_commons_logging",
        visibility = ["//visibility:public"],
        exports = ["@commons_logging_commons_logging//jar"],
    )

  if "org_springframework_spring_webmvc" not in excludes:
    native.java_library(
        name = "org_springframework_spring_webmvc",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_webmvc//jar"],
        runtime_deps = [
            ":org_springframework_spring_expression",
        ],
    )

  if "org_springframework_spring_expression" not in excludes:
    native.java_library(
        name = "org_springframework_spring_expression",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_expression//jar"],
    )

  if "org_springframework_security_spring_security_config" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_config",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_config//jar"],
        runtime_deps = [
            ":aopalliance_aopalliance",
            ":org_springframework_security_spring_security_core",
        ],
    )

  if "aopalliance_aopalliance" not in excludes:
    native.java_library(
        name = "aopalliance_aopalliance",
        visibility = ["//visibility:public"],
        exports = ["@aopalliance_aopalliance//jar"],
    )

  if "org_springframework_security_spring_security_core" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_core//jar"],
    )

  if "org_springframework_security_oauth_spring_security_oauth2" not in excludes:
    native.java_library(
        name = "org_springframework_security_oauth_spring_security_oauth2",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_oauth_spring_security_oauth2//jar"],
        runtime_deps = [
            ":commons_codec_commons_codec",
        ],
    )

  if "commons_codec_commons_codec" not in excludes:
    native.java_library(
        name = "commons_codec_commons_codec",
        visibility = ["//visibility:public"],
        exports = ["@commons_codec_commons_codec//jar"],
    )

  if "org_slf4j_slf4j_api" not in excludes:
    native.java_library(
        name = "org_slf4j_slf4j_api",
        visibility = ["//visibility:public"],
        exports = ["@org_slf4j_slf4j_api//jar"],
    )

