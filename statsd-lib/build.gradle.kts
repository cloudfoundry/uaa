plugins {
    java
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
    
    testImplementation(libs.mockitoJunit5)
    testImplementation(libs.bytebuddy)
    testImplementation(libs.bytebuddyagent)

    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)
    implementation(libs.jacksonDatabind)
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