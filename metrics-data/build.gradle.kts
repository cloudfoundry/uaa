plugins {
    java
    alias(libs.plugins.springDependencyManagement)
    alias(libs.plugins.jacocoLog)
    alias(libs.plugins.sonarqube)
}

description = "CloudFoundry Identity Metrics Data Jar"

dependencies {
    implementation(libs.jacksonDatabind)
    implementation(libs.jacksonAnnotations)

    testImplementation(libs.springBootStarterTest) {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation(libs.hamcrest)
    testImplementation(libs.junit5JupiterApi)
    testImplementation(libs.junit5JupiterParams)
    testImplementation(libs.junit5JupiterEngine)
    testImplementation(libs.unboundIdLdapSdk)

    testRuntimeOnly(libs.jacocoAgent)
    testRuntimeOnly(libs.junit5PlatformLauncher)

    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)
}

tasks.named<ProcessResources>("processResources") {
    //maven replaces project.artifactId in the log4j2.properties file
    //https://www.pivotaltracker.com/story/show/74344574
    filter { line: String -> 
        if (line.contains("\${project.artifactId}")) {
            line.replace("\${project.artifactId}", "cloudfoundry-identity-metrics-data")
        } else {
            line
        }
    }
}