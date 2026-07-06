plugins {
    java
    alias(libs.plugins.springDependencyManagement)
    alias(libs.plugins.jacocoLog)
    alias(libs.plugins.sonarqube)
}

description = "CloudFoundry Identity Model JAR"

dependencies {
    implementation(project(":cloudfoundry-identity-metrics-data"))

    implementation(libs.jacksonDatabind)
    implementation(libs.jacksonAnnotations)

    implementation(libs.jakartaValidationApi)

    implementation(libs.commonsCodec)
    implementation(libs.commonsIo)

    implementation(libs.springWeb)
    implementation(libs.springWebMvc)
    implementation(libs.springSecurityConfig)

    implementation(libs.nimbusJwt)

    implementation(libs.slf4jApi)

    testImplementation(libs.springBootStarterTest) {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation(libs.hamcrest)
    testImplementation(libs.junit5JupiterApi)
    testImplementation(libs.junit5JupiterParams)
    testImplementation(libs.junit5JupiterEngine)
    testRuntimeOnly(libs.jacocoAgent)
    testRuntimeOnly(libs.junit5PlatformLauncher)

    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)
}

val testArtifacts by configurations.creating

val testJar by tasks.registering(Jar::class) {
    dependsOn(tasks.testClasses)
    archiveClassifier.set("tests")
    from(sourceSets.test.get().output)
}

artifacts {
    add("testArtifacts", testJar)
}

apply(from = file("build_properties.gradle.kts"))

tasks.named<ProcessResources>("processResources") {
    //maven replaces project.artifactId in the log4j2.properties file
    //https://www.pivotaltracker.com/story/show/74344574
    filter { line: String ->
        if (line.contains("\${project.artifactId}")) {
            line.replace("\${project.artifactId}", "cloudfoundry-identity-model")
        } else {
            line
        }
    }
}

tasks.register<Test>("integrationTest") {
    onlyIf { //disable since we don't have any
        false
    }
}