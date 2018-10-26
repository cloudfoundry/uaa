load("@io_bazel_rules_appengine//appengine:java_appengine.bzl", "appengine_war")

package(
    default_visibility = ["//visibility:public"],
)

exports_files(["src/main/resources/required_configuration.yml"])

appengine_war(
    name = "uaa",
    jars = [
        "//metrics-data",
        "//model",
        "//server",
    ],
    data = glob([
        "src/main/webapp/**",
        #"src/main/resources/**",
    ]),
    data_path = "/uaa/src/main/webapp",
    #data_path = "/webapp",
)
