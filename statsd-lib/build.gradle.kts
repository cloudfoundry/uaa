plugins {
    java
    alias(libs.plugins.springDependencyManagement)
    alias(libs.plugins.jacocoLog)
    alias(libs.plugins.sonarqube)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":cloudfoundry-identity-metrics-data"))
    implementation(libs.springBootStarter)
    implementation(libs.springBootStarterWeb)
    implementation(libs.springBootStarterLog4j2)
    implementation(libs.statsdClient)
    implementation(libs.jacksonDatabind)

    testImplementation(libs.springBootStarterTest) {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation(libs.junit5JupiterApi)
    testImplementation(libs.junit5JupiterParams)
    testImplementation(libs.junit5JupiterEngine)
    testImplementation(libs.mockitoJunit5)

    testRuntimeOnly(libs.jacocoAgent)
    testRuntimeOnly(libs.junit5PlatformLauncher)

    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)
}

tasks.named<Test>("test") {
    exclude("org/cloudfoundry/identity/statsd/integration/*.class")
    exclude("**/*IT.class")
}

tasks.register<Test>("integrationTest") {
    filter {
        includeTestsMatching("org.cloudfoundry.identity.statsd.integration.*")
        includeTestsMatching("*IT")
    }
}