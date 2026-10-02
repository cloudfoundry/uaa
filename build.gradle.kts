import org.apache.tools.ant.filters.ReplaceTokens
import java.nio.file.Path
import java.nio.file.Paths

// Local-dev-only DB credentials for the mysql/postgresql profiles, matching the database
// bootstrapped by README.md / scripts/lib_db_helper.sh / scripts/docker-compose.yml.
// These are intentionally not shipped in application-mysql.properties/application-postgresql.properties
// (which are packaged into the WAR), so callers that boot a real mysql/postgresql locally must
// supply them here instead. Override any of them with the matching -D system property.
fun localDatabaseCredentialArgs(activeProfiles: String): Map<String, String> {
    val profiles = activeProfiles.split(",").map { it.trim() }
    return when {
        profiles.contains("mysql") -> mapOf(
            "database.username" to System.getProperty("database.username", "root"),
            "database.password" to System.getProperty("database.password", "changeme"),
            "database.url" to System.getProperty("database.url", "jdbc:mysql://127.0.0.1:3306/uaa?useSSL=true&trustServerCertificate=true"),
        )
        profiles.contains("postgresql") -> mapOf(
            "database.username" to System.getProperty("database.username", "root"),
            "database.password" to System.getProperty("database.password", "changeme"),
            "database.url" to System.getProperty("database.url", "jdbc:postgresql:uaa"),
        )
        else -> emptyMap()
    }
}

plugins {
    alias(libs.plugins.springDependencyManagement) apply false
    alias(libs.plugins.springBoot) apply false
    alias(libs.plugins.jacocoLog) apply false
    alias(libs.plugins.sonarqube) // Applied to root for global configuration
}

allprojects {
    repositories {
        mavenCentral()
        maven {
            url = uri("https://build.shibboleth.net/nexus/content/repositories/releases/")
        }
        maven { 
            url = uri("https://repository.mulesoft.org/releases/") 
        }
    }
}

subprojects {
    /** Log each test PASSED/SKIPPED/FAILED unless disabled (-PverboseTests=false or UAA_VERBOSE_TESTS=0/off). */
    val uaaVerboseTestRaw = (findProperty("verboseTests") ?: System.getenv("UAA_VERBOSE_TESTS") ?: "true")
            .toString().trim().lowercase()
    val uaaVerboseTestEvents = !listOf("false", "0", "off", "no").contains(uaaVerboseTestRaw)

    // Configure Java version for all projects with Java plugin applied
    plugins.withType<JavaPlugin> {
        configure<JavaPluginExtension> {
            sourceCompatibility = JavaVersion.VERSION_25
            targetCompatibility = JavaVersion.VERSION_25
        }
    }

    // Use afterEvaluate to access version catalog after project evaluation
    afterEvaluate {
        // Override Spring Boot managed dependency versions using ext properties
        // See: https://docs.spring.io/spring-boot/appendix/dependency-versions/properties.html
        extra["tomcat.version"] = libs.versions.tomcat.get()
        extra["commons-codec.version"] = libs.versions.commonsCodec.get()
        extra["selenium.version"] = libs.versions.selenium.get()
        extra["jackson-2-bom.version"] = libs.versions.jackson2.get()
        extra["jackson-bom.version"] = libs.versions.jackson.get()
        extra["postgresql.version"] = libs.versions.postgresql.get()

        configure<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension> {
            imports {
                mavenBom(libs.springBootBom.get().toString())
            }
            
            // Libraries that have version conflicts (not managed by BOMs above)
            dependencies {
                // Guava - multiple versions from different transitive deps
                dependency("com.google.guava:guava:${libs.versions.guava.get()}")
            }
        }
    }

    configurations.configureEach {
        exclude(group = "org.hamcrest", module = "hamcrest-all")
        exclude(group = "org.hamcrest", module = "hamcrest-core")
        exclude(group = "org.hamcrest", module = "hamcrest-library")
        exclude(group = "org.springframework.boot", module = "spring-boot-starter-logging")
        exclude(group = "org.apache.directory.server", module = "apacheds-core")
        exclude(group = "org.apache.directory.server", module = "apacheds-protocol-ldap")
        exclude(group = "org.skyscreamer", module = "jsonassert")
        exclude(group = "com.vaadin.external.google", module = "android-json")
        exclude(group = "com.unboundid.components", module = "json")

        // Exclude opensaml-security-api and non-FIPS bouncycastle libs, and use Shadow library for FIPS compliance
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcutil-jdk15on")
        exclude(group = "org.bouncycastle", module = "bcprov-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
        exclude(group = "org.bouncycastle", module = "bcutil-jdk18on")

        resolutionStrategy {
            eachDependency { 
                // Dependencies not managed by any BOM
                // OpenSAML modules - align for migration
                if (requested.group == "org.opensaml" && requested.name.startsWith("opensaml-")) {
                    useVersion(libs.versions.opensaml.get())
                    because("Pinning all opensaml modules to the same version for OpenSAML 5 migration.")
                }
                // Cryptacular - avoid regressions, explicit downgrade to 1.2.6
                else if (requested.group == "org.cryptacular" && requested.name == "cryptacular") {
                    useVersion(libs.versions.cryptacular.get())
                    because("Pinning cryptacular to avoid regressions from newer OpenSAML versions.")
                }
            }
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.compilerArgs.addAll(listOf("-Xlint:none", "-nowarn", "-parameters"))
    }

    tasks.withType<Test>().configureEach {
        // when failFast = true AND retry is on, there is a serious issue:
        // Gradle might stop the test run due to the failFast but still concludes with BUILD SUCCESSFUL (if the retry is successful)
        failFast = false
        useJUnitPlatform()
        // Increased to 1536m for Spring Boot 4 compatibility
        jvmArgs(
            "-Xmx1536m",
            "-Xms512m",
            "-XX:MaxMetaspaceSize=512m",
            "-XX:+UseG1GC",
            "-XX:+StartAttachListener",
            "-XX:+HeapDumpOnOutOfMemoryError",
            "-XX:HeapDumpPath=/var/log/uaa-tests.hprof"
        )

        // Enable test timing to identify slow tests
        // This helps debug CI performance issues
        reports {
            junitXml.required.set(true)
            html.required.set(true)
        }

        testLogging {
            if (uaaVerboseTestEvents) {
                events("passed", "skipped", "failed")
            } else {
                events("failed")
            }
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            // Set showStandardStreams=true to see all standard output from tests (there's a ton of it!)
            showStandardStreams = false
            showCauses = true
            showExceptions = true
            showStackTraces = true
        }

        // Add system property to enable detailed test timing
        systemProperty("junit.jupiter.execution.timeout.default", System.getProperty("junit.jupiter.execution.timeout.default", "0"))

        // ByteBuddy 1.18.x auto-disables Unsafe-based class definition on Java 26+ (used as a
        // fallback by XMLUnit/Mockito when generating dynamic subclasses/proxies). Despite the
        // wording of ByteBuddy's own exception message ("set net.bytebuddy.safe to true if you
        // want to use the unsafe API"), the property is named for "safe mode": true means disable
        // Unsafe, so it must be explicitly set to false here to keep the legacy behavior working
        // until ByteBuddy ships a default method-handle-based injection path.
        // See: net.bytebuddy.dynamic.loading.ClassInjector$UsingUnsafe$Dispatcher$CreationAction
        systemProperty("net.bytebuddy.safe", "false")

        // Log slow tests to help identify bottlenecks
        addTestListener(object : TestListener {
            override fun beforeSuite(suite: TestDescriptor) {}
            override fun beforeTest(testDescriptor: TestDescriptor) {}
            override fun afterTest(testDescriptor: TestDescriptor, result: TestResult) {
                val duration = result.endTime - result.startTime
                if (duration > 10000) { // 10 seconds
                    logger.warn("SLOW TEST: ${testDescriptor.className}.${testDescriptor.name} took ${duration}ms")
                }
            }
            override fun afterSuite(suite: TestDescriptor, result: TestResult) {
                if (suite.parent == null) {
                    val duration = result.endTime - result.startTime
                    val testLabel = if (result.testCount == 1L) "unit-test" else "unit-tests"
                    logger.lifecycle("[${project.name}] Completed ${result.testCount} $testLabel in ${duration}ms (passed=${result.successfulTestCount};failed=${result.failedTestCount};skipped=${result.skippedTestCount})")
                }
            }
        })
    }

    tasks.register<DependencyReportTask>("allDeps") {}

    tasks.register("writeNewPom") {
        doLast {
            // This task is deprecated - just create a simple POM
            file("./pom.xml").writeText("""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.cloudfoundry.identity</groupId>
    <artifactId>cloudfoundry-identity-parent</artifactId>
    <version>${version}</version>
    <packaging>pom</packaging>
    <name>CloudFoundry Identity Parent</name>
    <licenses>
        <license>
            <name>The Apache Software License, Version 2.0</name>
            <url>http://www.apache.org/licenses/LICENSE-2.0.txt</url>
            <distribution>repo</distribution>
        </license>
    </licenses>
</project>""")
        }
    }

    repositories {
        mavenCentral()
        maven {
            url = uri("https://repo.maven.apache.org/maven2")
        }
    }
}

configure<org.sonarqube.gradle.SonarExtension> {
    properties {
        property("sonar.projectKey", "cloudfoundry-identity-parent")
        property("sonar.organization", "cloudfoundry-1")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.exclusions", "samples/**/*.*,**/*Test.java,**/*Tests.java,**/*IT.java,**/*SecurityConfiguration.java")
        property("sonar.java.source", JavaVersion.current())
    }
}

gradle.taskGraph.whenReady {
    allprojects.forEach { proj ->
        proj.tasks.withType<Test>().forEach { testTask ->
            val activeProfiles = System.getProperty("spring.profiles.active", "hsqldb")
            testTask.systemProperty("spring.profiles.active", activeProfiles)
            testTask.systemProperty("testId", System.getProperty("testId", ""))
            testTask.systemProperty("zones.paths.enabled", System.getProperty("zones.paths.enabled", "true"))
            // Only the integrationTest task connects to a real external mysql/postgresql (via CI service
            // containers) with no other source of connection details now that application-mysql.properties/
            // application-postgresql.properties no longer ship them. Scoped to this task name only: the plain
            // `test` task includes tests (DatabasePropertiesTest, YamlServletProfileInitializerTest) that
            // deliberately exercise their own per-profile/custom database property fixtures, which a
            // blanket system property override would incorrectly clobber.
            if (testTask.name == "integrationTest") {
                localDatabaseCredentialArgs(activeProfiles).forEach { (key, value) -> testTask.systemProperty(key, value) }
            }
        }
    }
}

tasks.register<Copy>("manifests") {
    dependsOn(subprojects.map { it.tasks.named("assemble") })
    from("uaa/src/test/resources/sample-manifests") {
        include("**/*.yml")
        filter<ReplaceTokens>(
            "tokens" to mapOf(
                "version" to version,
                "app" to System.getProperty("app", "myuaa"),
                "appdomain" to System.getProperty("app-domain", "bosh-lite.com")
            )
        )
    }
    into("build/sample-manifests")
}

tasks.register("cleanBootTomcatDir") {
    doLast {
        val tomcatBase = file("scripts/boot/tomcat/").absolutePath
        delete(Path.of(tomcatBase))
        Paths.get(tomcatBase, "work").toFile().mkdirs()
        Paths.get(tomcatBase, "webapps").toFile().mkdirs()
    }
}

tasks.register<JavaExec>("bootWarRun") {
    dependsOn("cleanBootTomcatDir")
    dependsOn(subprojects.map { it.tasks.named("assemble") })
    classpath(files(file("uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war")))
    systemProperty("server.tomcat.basedir", file("scripts/boot/tomcat/").absolutePath)
    systemProperty("SECRETS_DIR", System.getProperty("SECRETS_DIR", file("scripts/boot").absolutePath))
    val activeProfiles = System.getProperty("spring.profiles.active", "hsqldb")
    systemProperty("spring.profiles.active", activeProfiles)
    localDatabaseCredentialArgs(activeProfiles).forEach { (key, value) -> systemProperty(key, value) }
    systemProperty("metrics.perRequestMetrics", System.getProperty("metrics.perRequestMetrics", "true"))
    systemProperty("smtp.host", "localhost")
    systemProperty("smtp.port", 2525)
    systemProperty("java.security.egd", "file:/dev/./urandom")
    systemProperty("CLOUDFOUNDRY_CONFIG_PATH", file("scripts/boot").absolutePath)
    systemProperty("server.servlet.context-path", "/uaa")
    systemProperty("statsd.enabled", "true")
    systemProperty("logging.config", file("scripts/boot/log4j2.properties").absolutePath)
    systemProperty("zones.paths.enabled", System.getProperty("zones.paths.enabled", "true"))
}

tasks.register<Exec>("killUaa") {
    workingDir("./")
    executable = "scripts/kill_uaa.sh"
}

/**
 * Writes the resolved tomcat-embed-core version (from the Spring Boot BOM) to
 * {@code build/tomcat-distribution.version} for scripts that download a matching
 * Apache Tomcat binary distribution (standalone integration tests).
 */
tasks.register("writeTomcatDistributionVersion") {
    group = "build"
    description = "Writes build/tomcat-distribution.version from tomcat-embed-core on cloudfoundry-identity-uaa runtimeClasspath"
    val uaaProject = project(":cloudfoundry-identity-uaa")
    val outFile = layout.buildDirectory.file("tomcat-distribution.version")
    outputs.file(outFile)
    doLast {
        val cfg = uaaProject.configurations.named("runtimeClasspath").get()
        val artifact = cfg.resolvedConfiguration.resolvedArtifacts.find { it.name == "tomcat-embed-core" }
        if (artifact == null) {
            throw GradleException("Could not resolve tomcat-embed-core version from :cloudfoundry-identity-uaa runtimeClasspath")
        }
        outFile.get().asFile.parentFile.mkdirs()
        outFile.get().asFile.writeText(artifact.moduleVersion.id.version)
    }
}

tasks.register("printTomcatDistributionVersion") {
    group = "help"
    description = "Prints the Apache Tomcat version matching Spring Boot embedded tomcat-embed-core"
    dependsOn("writeTomcatDistributionVersion")
    doLast {
        println(file("${layout.buildDirectory.get().asFile}/tomcat-distribution.version").readText().trim())
    }
}

tasks.register("run") {
    dependsOn("killUaa")
    dependsOn(":cloudfoundry-identity-uaa:bootRun")
    description = "Kills any running UAA and starts the application. Use -Pdebug to enable debug mode (starts immediately) or -Pdebugs to enable debug mode with suspend (waits for debugger). Default port 5005, configurable with -PdebugPort=<port>"
    group = "application"
}