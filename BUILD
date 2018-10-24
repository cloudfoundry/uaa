sh_binary(
    name = "run_local",
    srcs = ["run_local.sh"],
    data = [
        "//uaa:uaa.war",
        "//uaa:src/main/resources/required_configuration.yml",
        "@apache_tomcat//:apache_tomcat_lib",
    ],
)
