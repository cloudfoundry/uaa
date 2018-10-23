def generated_maven_jars():
  excludes = native.existing_rules().keys()

  if "cglib_cglib" not in excludes:
    native.maven_jar(
        name = "cglib_cglib",
        artifact = "cglib:cglib:3.2.5",
        repository = "https://repo1.maven.org/maven2/",
    )

def generated_java_libraries():
  excludes = native.existing_rules().keys()

  if "cglib_cglib" not in excludes:
    native.maven_jar(
        name = "cglib_cglib",
        visibility = ["//visibility:public"],
        exports = ["@cglib_cglib//jar"],
    )

