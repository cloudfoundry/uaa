load("//metrics-data:generate_workspace.bzl", "generated_maven_jars")
generated_maven_jars()

load("//model:generate_workspace.bzl", "generated_maven_jars")
generated_maven_jars()

load("//server:generate_workspace.bzl", "generated_maven_jars")
generated_maven_jars()

# needed to deploy WARs with Tomcat?
maven_jar(
    name = "javax_servlet_api",
    artifact = "javax.servlet:javax.servlet-api:3.1.0",
)

# non-AppEngine WAR???
load("//uaa:war_rules.bzl", "war_file")
