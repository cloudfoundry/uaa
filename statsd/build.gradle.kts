plugins {
    war
    alias(libs.plugins.springBoot)
    alias(libs.plugins.springDependencyManagement)
    alias(libs.plugins.jacocoLog)
    alias(libs.plugins.sonarqube)
}

tasks.named<War>("war") {
    archiveBaseName.set("cloudfoundry-identity-statsd")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":cloudfoundry-identity-statsd-lib"))
    implementation(libs.springBootStarterWeb)
    providedRuntime(libs.springBootStarterTomcatRuntime)

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

tasks.named<Test>("test") {
    exclude("org/cloudfoundry/identity/statsd/integration/*.class")
    exclude("**/*IT.class")
}

tasks.register<Test>("integrationTest") {
    onlyIf { //disable since we don't have any
        false
    }
}

tasks.named("bootRun") {
    enabled = false
}