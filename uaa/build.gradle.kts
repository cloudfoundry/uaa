import org.gradle.process.ExecOperations
import javax.inject.Inject

val identityServer = parent!!.subprojects.find { "cloudfoundry-identity-server" == it.name }!!

plugins {
    war
    alias(libs.plugins.springBoot)
    alias(libs.plugins.springDependencyManagement)
    alias(libs.plugins.jacocoLog)
    alias(libs.plugins.sonarqube)
}

tasks.named<ProcessResources>("processResources") {
    //maven replaces project.artifactId in the log4j2.properties file
    //https://www.pivotaltracker.com/story/show/74344574
    from(File("../common/src/main/resources/log4j2.properties"))
    filter { line: String ->
        if (line.contains("\${project.artifactId}")) {
            line.replace("\${project.artifactId}", "cloudfoundry-identity-uaa")
        } else {
            line
        }
    }
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootWar>("bootWar") {
    archiveClassifier.set("")
    //archiveClassifier = 'boot'
    isEnabled = true
}

tasks.named<Jar>("jar") { 
    isEnabled = false 
}

tasks.named<War>("war") {
    archiveClassifier.set("")
    isEnabled = false
    //workaround for maven <scope>optional</scope>
    rootSpec.exclude("**/spring-security-oauth-*.jar")
}

repositories {
    maven { url = uri("https://build.shibboleth.net/nexus/content/repositories/releases/") }
}

description = "UAA"

dependencies {
    implementation(project(":cloudfoundry-identity-server")) {
        exclude(module = "jna")
    }
    implementation(project(":cloudfoundry-identity-statsd-lib"))
    implementation(project(":cloudfoundry-identity-model"))
    implementation(libs.springSecurityConfig)
    implementation(libs.springSecurityWeb)
    implementation(libs.springBootStarter)
    implementation(libs.springBootStarterWeb)
    implementation(libs.thymeLeaf) {
        exclude(module = "ognl")
    }
    implementation(libs.thymeleafSpring) {
        exclude(module = "ognl")
    }
    implementation(libs.thymeleafDialect) {
        exclude(module = "ognl")
    }
    implementation(libs.thymeleafExtrasSpringSecurity) {
        exclude(module = "ognl")
    }
    implementation(libs.braveInstrumentation)
    implementation(libs.braveContextSlf4j)

    // OpenAPI documentation
    implementation(libs.springDocOpenapi)

    implementation(libs.springWeb)
    implementation(libs.springWebMvc)
    implementation(libs.bouncyCastleFipsProv)

    runtimeOnly(libs.aspectJWeaver)
    runtimeOnly(libs.postgresql)
    runtimeOnly(libs.mariaJdbcDriver)

    testImplementation(identityServer.sourceSets.test.get().output)
    testImplementation(libs.springBootStarterTest) {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation(libs.hamcrest)
    testImplementation(libs.junit5JupiterApi)
    testImplementation(libs.junit5JupiterParams)
    testImplementation(libs.junit5JupiterEngine)
    testImplementation(libs.unboundIdLdapSdk)
    testImplementation(project(":cloudfoundry-identity-model"))
    testImplementation(project(":cloudfoundry-identity-metrics-data"))
    testImplementation(libs.flywayCore)
    testImplementation(libs.hibernateValidator)
    testImplementation(libs.selenium)
    testImplementation(libs.seleniumRemoteDriver)
    testImplementation(libs.seleniumHttp)
    testImplementation(libs.orgJson)
    testImplementation(libs.springBootStarterLog4j2)
    testImplementation(libs.springContextSupport)
    testImplementation(libs.springSessionJdbc)
    testImplementation(libs.springTest)
    testImplementation(libs.springSecurityLdap)
    testImplementation(libs.springSecurityTest)
    testImplementation(libs.springBootStarterMail)
    testImplementation(libs.passay)
    testImplementation(libs.mockitoJunit5)
    testImplementation(libs.springRestdocs)
    testImplementation(libs.greenmail)
    testImplementation(libs.commonsIo)
    testImplementation(libs.apacheHttpClient)
    testImplementation(libs.openSamlApi)
    testImplementation(libs.xmlUnit)
    testImplementation(libs.awaitility)
    testImplementation(libs.nimbusJwt)

    testRuntimeOnly(libs.jacocoAgent)
    testRuntimeOnly(libs.junit5PlatformLauncher)

    compileOnly(libs.tomcatEmbed)
    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)
}

extra["snippetsDir"] = file("build/generated-snippets")

tasks.named<Test>("test") {
    exclude("org/cloudfoundry/identity/uaa/integration/*.class")
    exclude("**/*IT.class")
    exclude("**/*Docs.class")
    systemProperty("mock.suite.test", "true")

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Running tests in parallel
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Count available cores. We assume 2 logical cores per physical core.
    // In case there is only one vCPU, we count 1 full core.
    val availableCpus = maxOf(Runtime.getRuntime().availableProcessors() / 2.0, 1.0)

    // We want some amount of parallelism, but it does not make sense to run too many
    // tests in parallel, see docs/testing. We target 4 tests in parallel at most. If
    // there are less CPUs available, we use all available CPUs but no more.
    maxParallelForks = minOf(availableCpus, 4.0).toInt()
}

tasks.register("populateVersionfile") {
    doLast {
        val versionFile = File("$projectDir/slateCustomizations/source/versionfile")
        versionFile.createNewFile()
        assert(versionFile.exists())
        versionFile.writeText(version.toString().substring(0, version.toString().lastIndexOf(".")) + ".0")
    }
}

tasks.register<Copy>("customizeSlate") {
    dependsOn(tasks.named("populateVersionfile"))
    from("slate")
    from("slateCustomizations")
    into("build/slate")
}

tasks.register<Test>("docsTestRestDocs") {
    dependsOn(tasks.named("testClasses"))
    useJUnitPlatform()
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    include("**/*Docs.class")
    systemProperty("docs.build.generated.snippets.dir", file("build/generated-snippets").absolutePath)
}

tasks.register<Exec>("gemInstallBundle") {
    dependsOn("customizeSlate")
    workingDir(file("build/slate"))
    executable = "gem"
    args("install", "bundler:2.7.1")
}

tasks.register<Exec>("bundleInstall") {
    dependsOn(tasks.named("gemInstallBundle"))
    dependsOn("customizeSlate")
    workingDir(file("build/slate"))
    executable = "bundle"
    args("install")
}

tasks.register<Delete>("deleteDefaultContent") {
    delete("build/slate/source/index.html.md")
}

tasks.register<Exec>("slate") {
    dependsOn("customizeSlate", "deleteDefaultContent", "bundleInstall", "docsTestRestDocs")
    workingDir(file("build/slate"))
    executable = "bundle"
    args("exec", "middleman", "build", "--verbose", "--build-dir=../docs/version/" + version.toString().substring(0, version.toString().lastIndexOf(".")) + ".0")
}

tasks.register("generateDocs") {
    dependsOn("slate")
}

// Gradle bootBuildImage task configuration
tasks.named<org.springframework.boot.gradle.tasks.bundling.BootBuildImage>("bootBuildImage") {
    imageName.set("cloudfoundry/uaa:$version")
    var doDebug = false
    val activeSpringProfiles = (System.getProperty("spring.profiles.active", "")?.split(",") ?: emptyList())
    if (activeSpringProfiles.contains("debugs") || System.getProperty("xdebugs")?.toBoolean() == true ||
        activeSpringProfiles.contains("debug") || System.getProperty("xdebug")?.toBoolean() == true) {
        doDebug = true
    }
    // https://github.com/paketo-buildpacks/bellsoft-liberica
    // use JRE since JDK gets too big
    environment.set(mapOf<String, String>(
        "BP_SPRING_CLOUD_BINDINGS_DISABLED" to "true",
        "BP_JVM_VERSION" to "25",
        "BP_JVM_TYPE" to (System.getenv("BP_JVM_TYPE") ?: project.findProperty("BP_JVM_TYPE") ?: "JRE").toString(),
        "BP_JVM_PLATFORM" to "liberica"
    ))
    if (doDebug) {
        environment.set(environment.get() + mapOf<String, String>(
            "BPL_DEBUG_ENABLED" to "true",
            "BPL_DEBUG_PORT" to "5005"
        ))
    }
}

interface InjectedExecOps {
    @get:Inject val execOps: ExecOperations
}

tasks.register<Test>("integrationTest") {
    // Use the test source set and classpath
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    
    val injected = project.objects.newInstance<InjectedExecOps>()
    
    // Helper function to kill UAA process
    fun killUaa() {
        injected.execOps.exec {
            workingDir = rootProject.projectDir
            executable = "scripts/kill_uaa.sh"
        }
    }
    
    filter {
        includeTestsMatching("org.cloudfoundry.identity.uaa.integration.*")
        includeTestsMatching("*IT")
    }
    val samlUrlPropKey = "integration.test.saml.url"
    val samlUrl = System.getProperty(samlUrlPropKey)
    if (!samlUrl?.trim().isNullOrEmpty()) {
        systemProperty("integration.test.saml.url", samlUrl)
        project.logger.warn("UAA - Overriding SAML Url:$samlUrl")
    }

    val useExternalIntegrationServer = {
        val v = rootProject.findProperty("uaaIntegrationServer") ?: findProperty("uaaIntegrationServer") ?: System.getenv("UAA_INTEGRATION_SERVER")
        v != null && v.toString().lowercase() == "external"
    }

    doFirst {
        if (useExternalIntegrationServer()) {
            logger.lifecycle("UAA_INTEGRATION_SERVER=external (or -PuaaIntegrationServer=external): skipping embedded java -jar; tests expect UAA on port 8080")
            return@doFirst
        }
        logger.lifecycle("Killing UAA before auto-start")
        killUaa()

        val bootPidFile = rootProject.file("build/boot.pid")
        val bootLogFile = rootProject.file("build/boot.log")
        val springProfile = System.getProperty("spring.profiles.active", "hsqldb")
        val warFile = file("build/libs/cloudfoundry-identity-uaa-0.0.0.war")
        val bootDir = rootProject.file("scripts/boot")

        logger.lifecycle("Starting UAA application for integration tests...")

        val javaCmd = """nohup java \
            -DCLOUDFOUNDRY_CONFIG_PATH=${bootDir.absolutePath} \
            -DSECRETS_DIR=${bootDir.absolutePath} \
            -Dserver.servlet.context-path=/uaa \
            -Dsmtp.host=localhost \
            -Dsmtp.port=2525 \
            -Dspring.profiles.active=$springProfile \
            -jar ${warFile.absolutePath} > ${bootLogFile.absolutePath} 2>&1 & echo ${'$'}!"""

        val proc = ProcessBuilder("bash", "-c", javaCmd).start()
        proc.waitFor()
        val pid = proc.inputStream.bufferedReader().readText().trim()
        bootPidFile.writeText(pid)

        logger.lifecycle("UAA started with PID: $pid, waiting for it to be ready...")

        val maxWaitSeconds = 300
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < maxWaitSeconds * 1000) {
            if (bootLogFile.exists() && bootLogFile.readText().contains("Started UaaBootApplication")) {
                logger.lifecycle("UAA is ready!")
                return@doFirst
            }
            Thread.sleep(1000)
        }

        logger.lifecycle("Killing UAA after failed auto-start")
        killUaa()
        throw GradleException("UAA failed to start within $maxWaitSeconds seconds. Check ${bootLogFile.absolutePath}")
    }

    doLast {
        if (useExternalIntegrationServer()) {
            logger.lifecycle("Skipping embedded UAA shutdown; external Tomcat lifecycle is managed by the caller")
            return@doLast
        }
        logger.lifecycle("Stopping UAA application...")
        killUaa()
        rootProject.file("build/boot.pid").delete()
    }
    
    dependsOn(tasks.named("bootWar"))
}

tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootRun") {
    dependsOn(rootProject.tasks.named("cleanBootTomcatDir"))
    mainClass.set("org.cloudfoundry.experimental.boot.UaaBootApplication")
    systemProperty("logging.level.org.springframework.security", "TRACE")
    systemProperty("logging.config", file("../scripts/boot/log4j2.properties").absolutePath)
    systemProperty("uaa.boot.location.tomcat", System.getProperty("uaa.boot.location.tomcat", file("../scripts/boot/tomcat").absolutePath))
    systemProperty("spring.profiles.active", System.getProperty("spring.profiles.active", "hsqldb"))
    systemProperty("metrics.perRequestMetrics", System.getProperty("metrics.perRequestMetrics", "true"))
    systemProperty("smtp.host", "localhost")
    systemProperty("smtp.port", 2525)
    systemProperty("java.security.egd", "file:/dev/./urandom")
    systemProperty("CLOUDFOUNDRY_CONFIG_PATH", file("../scripts/boot").absolutePath)
    systemProperty("server.servlet.context-path", "/uaa")
    systemProperty("statsd.enabled", "true")

    // Enable debug mode if -Pdebug or -Pdebugs flag is provided
    if (project.hasProperty("debug") || project.hasProperty("debugs")) {
        val debugPort = project.findProperty("debugPort") ?: "5005"
        // debugs = suspend and wait for debugger, debug = start immediately
        val suspend = if (project.hasProperty("debugs")) "y" else "n"
        jvmArgs(
            "-agentlib:jdwp=transport=dt_socket,server=y,suspend=$suspend,address=*:$debugPort"
        )
        val mode = if (suspend == "y") "Suspended debug" else "Debug"
        logger.lifecycle("$mode mode enabled. Listening on port $debugPort")
    }
}