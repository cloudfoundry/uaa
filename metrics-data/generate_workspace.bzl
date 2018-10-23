def generated_maven_jars():
  excludes = native.existing_rules().keys()

  if "com_fasterxml_jackson_core_jackson_databind" not in excludes:
    native.maven_jar(
        name = "com_fasterxml_jackson_core_jackson_databind",
        artifact = "com.fasterxml.jackson.core:jackson-databind:jar:2.9.6",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_fasterxml_jackson_core_jackson_core" not in excludes:
    native.maven_jar(
        name = "com_fasterxml_jackson_core_jackson_core",
        artifact = "com.fasterxml.jackson.core:jackson-core:jar:2.9.6",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_fasterxml_jackson_core_jackson_annotations" not in excludes:
    native.maven_jar(
        name = "com_fasterxml_jackson_core_jackson_annotations",
        artifact = "com.fasterxml.jackson.core:jackson-annotations:jar:2.9.6",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_codehaus_jackson_jackson_mapper_asl" not in excludes:
    native.maven_jar(
        name = "org_codehaus_jackson_jackson_mapper_asl",
        artifact = "org.codehaus.jackson:jackson-mapper-asl:1.9.13",
        repository = "https://repo1.maven.org/maven2/",
    )

def generated_java_libraries():
  excludes = native.existing_rules().keys()

  if "com_fasterxml_jackson_core_jackson_databind" not in excludes:
    native.java_library(
        name = "com_fasterxml_jackson_core_jackson_databind",
        visibility = ["//visibility:public"],
        exports = ["@com_fasterxml_jackson_core_jackson_databind//jar"],
        runtime_deps = [
            ":com_fasterxml_jackson_core_jackson_core",
        ],
    )

  if "com_fasterxml_jackson_core_jackson_core" not in excludes:
    native.java_library(
        name = "com_fasterxml_jackson_core_jackson_core",
        visibility = ["//visibility:public"],
        exports = ["@com_fasterxml_jackson_core_jackson_core//jar"],
    )

  if "com_fasterxml_jackson_core_jackson_annotations" not in excludes:
    native.java_library(
        name = "com_fasterxml_jackson_core_jackson_annotations",
        visibility = ["//visibility:public"],
        exports = ["@com_fasterxml_jackson_core_jackson_annotations//jar"],
    )

  if "org_codehaus_jackson_jackson_mapper_asl" not in excludes:
    native.java_library(
        name = "org_codehaus_jackson_jackson_mapper_asl",
        visibility = ["//visibility:public"],
        exports = ["@org_codehaus_jackson_jackson_mapper_asl//jar"],
    )

