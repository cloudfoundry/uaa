plugins {
    war
    alias(libs.plugins.springDependencyManagement)
    alias(libs.plugins.jacocoLog)
    alias(libs.plugins.sonarqube)
}

description = "CloudFoundry Identity Server JAR"

dependencies {
    implementation(project(":cloudfoundry-identity-metrics-data"))
    implementation(project(":cloudfoundry-identity-model"))

    implementation(libs.tomcatJdbc)
    implementation(libs.jacksonDatabind)
    implementation(libs.jsonPath) {
        exclude(module = "json-smart")
    }
    implementation(libs.springBeans)
    implementation(libs.springContext)
    implementation(libs.springContextSupport)
    implementation(libs.springTx)
    implementation(libs.springJdbc)
    implementation(libs.springWeb)
    implementation(libs.springSecurityCore)
    implementation(libs.springSecurityAccess)
    implementation(libs.springSecurityWeb)
    implementation(libs.springSecurityConfig)
    implementation(libs.springBootStarterMail)
    implementation(libs.springBootSql)
    implementation(libs.springBootJdbc)
    implementation(libs.springBootTransaction)
    implementation(libs.openSamlApi)
    implementation(libs.springSecuritySamlServiceProvider)
    implementation(libs.xmlSecurity)
    implementation(libs.springSessionJdbc)

    implementation(libs.bouncyCastleFipsProv)
    implementation(libs.bouncyCastlePkixFips)
    implementation(libs.bouncyCastleTlsFips)
    implementation(libs.bouncyCastleUtilFips)

    implementation(libs.javaBuildpackClientCertificateMapper)

    implementation(libs.guava)

    implementation(libs.aspectJWeaver)

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

    implementation(libs.scim2SdkCommon)

    implementation(libs.hibernateValidator)
    implementation(libs.flywayHsqlDb)
    implementation(libs.flywayMySql)
    implementation(libs.flywayPostgresql)
    implementation(libs.springBootFlyway)
    implementation(libs.hsqldb)

    implementation(libs.snakeyaml)
    implementation(libs.velocity)

    implementation(libs.springWebMvc)
    implementation(libs.springSecurityLdap)
    implementation(libs.springLdapCore)
    implementation(libs.apacheLdapApi) {
        exclude(module = "slf4j-api")
        exclude(module = "mina-core")
    }

    implementation(libs.passay)

    implementation(libs.slf4jImpl)
    implementation(libs.log4jCore)

    implementation(libs.nimbusJwt)

    implementation(libs.apacheHttpClient)
    implementation(libs.commonsIo)

    testImplementation(project(mapOf("path" to ":cloudfoundry-identity-model", "configuration" to "testArtifacts")))

    testImplementation(libs.springBootStarterTest) {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
    testImplementation(libs.junit5JupiterApi)
    testImplementation(libs.junit5JupiterParams)
    testImplementation(libs.junit5JupiterEngine)
    testImplementation(libs.springTest)
    testImplementation(libs.mockitoJunit5)
    testImplementation(libs.orgJson)

    testImplementation(libs.postgresql)
    testImplementation(libs.mariaJdbcDriver)

    testImplementation(libs.tomcatElApi)
    testImplementation(libs.tomcatJasperEl)

    testImplementation(libs.xmlUnit)
    testImplementation(libs.awaitility)

    testRuntimeOnly(libs.jacocoAgent)
    testRuntimeOnly(libs.junit5PlatformLauncher)

    compileOnly(libs.tomcatEmbed)
    compileOnly(libs.lombok)
    annotationProcessor(libs.lombok)
}

configurations.configureEach {
    exclude(group = "org.beanshell", module = "bsh-core")
    exclude(group = "org.apache-extras.beanshell", module = "bsh")
    exclude(group = "com.fasterxml.woodstox", module = "woodstox-core")
    exclude(group = "commons-beanutils", module = "commons-beanutils")
    exclude(group = "commons-collections", module = "commons-collections")

    // Exclude non-FIPS bouncycastle libs, and use Shadow library for FIPS compliance
    exclude(group = "org.bouncycastle", module = "bcpkix-jdk15on")
    exclude(group = "org.bouncycastle", module = "bcprov-jdk15on")
    exclude(group = "org.bouncycastle", module = "bcutil-jdk15on")
    exclude(group = "org.bouncycastle", module = "bcprov-jdk18on")
    exclude(group = "org.bouncycastle", module = "bcpkix-jdk18on")
    exclude(group = "org.bouncycastle", module = "bcutil-jdk18on")
}

tasks.named<Jar>("jar") {
    exclude("org/cloudfoundry/identity/uaa/web/tomcat/UaaStartupFailureListener.*")
}

tasks.named<ProcessResources>("processResources") {
    //maven replaces project.artifactId in the log4j2.properties file
    //https://www.pivotaltracker.com/story/show/74344574
    filter { line: String ->
        if (line.contains("\${project.artifactId}")) {
            line.replace("\${project.artifactId}", "cloudfoundry-identity-server")
        } else {
            line
        }
    }
}

sourceSets.create("integrationTest") {
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations["integrationTestImplementation"].extendsFrom(configurations.testImplementation.get())
configurations["integrationTestRuntimeOnly"].extendsFrom(configurations.testRuntimeOnly.get())

tasks.register<Test>("integrationTest") {
    description = "Tests that run against the production implementation without test-scope class shadows."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform()
}

tasks.named("check") {
    dependsOn("integrationTest")
}

val tomcatListenerJar = tasks.register<Jar>("tomcatListenerJar") {
    archiveBaseName.set("tomcat-listener")
    from(sourceSets.main.get().output)
    include("org/cloudfoundry/identity/uaa/web/tomcat/UaaStartupFailureListener.*")
}

artifacts {
    add("archives", tomcatListenerJar)
}