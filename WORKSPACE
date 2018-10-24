load("//metrics-data:generate_workspace.bzl", "generated_maven_jars")
generated_maven_jars()

load("//model:generate_workspace.bzl", "generated_maven_jars")
generated_maven_jars()

load("//server:generate_workspace.bzl", "generated_maven_jars")
generated_maven_jars()

# needed to deploy WARs with Tomcat?
#maven_jar(
    #name = "javax_servlet_api",
    #artifact = "javax.servlet:javax.servlet-api:3.1.0",
#)

# needed to build deployable WAR
git_repository(
    name = "io_bazel_rules_appengine",
    remote = "https://github.com/bazelbuild/rules_appengine.git",
    # Check https://github.com/bazelbuild/rules_appengine/releases for the latest version.
    tag = "0.0.8",
)
load("@io_bazel_rules_appengine//appengine:java_appengine.bzl", "java_appengine_repositories")
java_appengine_repositories()

# used to run UAA locally
new_http_archive(
    name = "apache_tomcat",
    url = "http://apache.mirrors.tds.net/tomcat/tomcat-8/v8.0.53/bin/apache-tomcat-8.0.53.tar.gz",
    sha256 = "19a047c4425c4ea796215d397b7caeda958c764981624ea5c4f763d98d2db7fa",
    build_file = "BUILD.tomcat",
)
