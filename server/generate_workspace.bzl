def generated_maven_jars():
  excludes = native.existing_rules().keys()

  if "org_apache_tomcat_tomcat_jdbc" not in excludes:
    native.maven_jar(
        name = "org_apache_tomcat_tomcat_jdbc",
        artifact = "org.apache.tomcat:tomcat-jdbc:jar:8.5.32",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_tomcat_tomcat_juli" not in excludes:
    native.maven_jar(
        name = "org_apache_tomcat_tomcat_juli",
        artifact = "org.apache.tomcat:tomcat-juli:jar:8.5.32",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "javax_mail_mail" not in excludes:
    native.maven_jar(
        name = "javax_mail_mail",
        artifact = "javax.mail:mail:jar:1.4.7",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "javax_activation_activation" not in excludes:
    native.maven_jar(
        name = "javax_activation_activation",
        artifact = "javax.activation:activation:jar:1.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_logging_commons_logging" not in excludes:
    native.maven_jar(
        name = "commons_logging_commons_logging",
        artifact = "commons-logging:commons-logging:jar:1.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_jayway_jsonpath_json_path" not in excludes:
    native.maven_jar(
        name = "com_jayway_jsonpath_json_path",
        artifact = "com.jayway.jsonpath:json-path:jar:2.4.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "net_minidev_json_smart" not in excludes:
    native.maven_jar(
        name = "net_minidev_json_smart",
        artifact = "net.minidev:json-smart:jar:2.3",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "net_minidev_accessors_smart" not in excludes:
    native.maven_jar(
        name = "net_minidev_accessors_smart",
        artifact = "net.minidev:accessors-smart:jar:1.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_ow2_asm_asm" not in excludes:
    native.maven_jar(
        name = "org_ow2_asm_asm",
        artifact = "org.ow2.asm:asm:jar:5.0.4",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_slf4j_slf4j_api" not in excludes:
    native.maven_jar(
        name = "org_slf4j_slf4j_api",
        artifact = "org.slf4j:slf4j-api:jar:1.7.25",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_zxing_javase" not in excludes:
    native.maven_jar(
        name = "com_google_zxing_javase",
        artifact = "com.google.zxing:javase:jar:3.3.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_zxing_core" not in excludes:
    native.maven_jar(
        name = "com_google_zxing_core",
        artifact = "com.google.zxing:core:jar:3.3.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_beust_jcommander" not in excludes:
    native.maven_jar(
        name = "com_beust_jcommander",
        artifact = "com.beust:jcommander:jar:1.72",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_github_jai_imageio_jai_imageio_core" not in excludes:
    native.maven_jar(
        name = "com_github_jai_imageio_jai_imageio_core",
        artifact = "com.github.jai-imageio:jai-imageio-core:jar:1.3.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_beans" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_beans",
        artifact = "org.springframework:spring-beans:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_core",
        artifact = "org.springframework:spring-core:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_context" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_context",
        artifact = "org.springframework:spring-context:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_aop" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_aop",
        artifact = "org.springframework:spring-aop:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_expression" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_expression",
        artifact = "org.springframework:spring-expression:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_tx" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_tx",
        artifact = "org.springframework:spring-tx:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_jdbc" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_jdbc",
        artifact = "org.springframework:spring-jdbc:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_web" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_web",
        artifact = "org.springframework:spring-web:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_context_support" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_context_support",
        artifact = "org.springframework:spring-context-support:jar:4.3.18.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_core",
        artifact = "org.springframework.security:spring-security-core:jar:4.2.7.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "aopalliance_aopalliance" not in excludes:
    native.maven_jar(
        name = "aopalliance_aopalliance",
        artifact = "aopalliance:aopalliance:jar:1.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_jwt" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_jwt",
        artifact = "org.springframework.security:spring-security-jwt:jar:1.0.8.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_httpcomponents_httpclient" not in excludes:
    native.maven_jar(
        name = "org_apache_httpcomponents_httpclient",
        artifact = "org.apache.httpcomponents:httpclient:jar:4.5.3",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_httpcomponents_httpcore" not in excludes:
    native.maven_jar(
        name = "org_apache_httpcomponents_httpcore",
        artifact = "org.apache.httpcomponents:httpcore:jar:4.4.6",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_codec_commons_codec" not in excludes:
    native.maven_jar(
        name = "commons_codec_commons_codec",
        artifact = "commons-codec:commons-codec:jar:1.9",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_openid" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_openid",
        artifact = "org.springframework.security:spring-security-openid:jar:4.2.7.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_inject_guice" not in excludes:
    native.maven_jar(
        name = "com_google_inject_guice",
        artifact = "com.google.inject:guice:jar:2.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_openid4java_openid4java_nodeps" not in excludes:
    native.maven_jar(
        name = "org_openid4java_openid4java_nodeps",
        artifact = "org.openid4java:openid4java-nodeps:jar:0.9.6",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "net_jcip_jcip_annotations" not in excludes:
    native.maven_jar(
        name = "net_jcip_jcip_annotations",
        artifact = "net.jcip:jcip-annotations:jar:1.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "net_sourceforge_nekohtml_nekohtml" not in excludes:
    native.maven_jar(
        name = "net_sourceforge_nekohtml_nekohtml",
        artifact = "net.sourceforge.nekohtml:nekohtml:jar:1.9.20",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "xerces_xercesImpl" not in excludes:
    native.maven_jar(
        name = "xerces_xercesImpl",
        artifact = "xerces:xercesImpl:jar:2.10.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_web" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_web",
        artifact = "org.springframework.security:spring-security-web:jar:4.2.7.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_extensions_spring_security_saml2_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_extensions_spring_security_saml2_core",
        artifact = "org.springframework.security.extensions:spring-security-saml2-core:jar:1.0.4.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "ca_juliusdavies_not_yet_commons_ssl" not in excludes:
    native.maven_jar(
        name = "ca_juliusdavies_not_yet_commons_ssl",
        artifact = "ca.juliusdavies:not-yet-commons-ssl:jar:0.3.17",
        repository = "https://repository.mulesoft.org/releases/",
    )

  if "commons_beanutils_commons_beanutils" not in excludes:
    native.maven_jar(
        name = "commons_beanutils_commons_beanutils",
        artifact = "commons-beanutils:commons-beanutils:jar:1.9.3",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_fileupload_commons_fileupload" not in excludes:
    native.maven_jar(
        name = "commons_fileupload_commons_fileupload",
        artifact = "commons-fileupload:commons-fileupload:jar:1.3.3",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_io_commons_io" not in excludes:
    native.maven_jar(
        name = "commons_io_commons_io",
        artifact = "commons-io:commons-io:jar:2.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_santuario_xmlsec" not in excludes:
    native.maven_jar(
        name = "org_apache_santuario_xmlsec",
        artifact = "org.apache.santuario:xmlsec:jar:1.5.8",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_velocity_velocity_engine_core" not in excludes:
    native.maven_jar(
        name = "org_apache_velocity_velocity_engine_core",
        artifact = "org.apache.velocity:velocity-engine-core:jar:2.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_commons_commons_lang3" not in excludes:
    native.maven_jar(
        name = "org_apache_commons_commons_lang3",
        artifact = "org.apache.commons:commons-lang3:jar:3.5",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_opensaml_opensaml" not in excludes:
    native.maven_jar(
        name = "org_opensaml_opensaml",
        artifact = "org.opensaml:opensaml:jar:2.6.6",
        repository = "https://build.shibboleth.net/nexus/content/repositories/releases/",
    )

  if "org_opensaml_openws" not in excludes:
    native.maven_jar(
        name = "org_opensaml_openws",
        artifact = "org.opensaml:openws:jar:1.5.6",
        repository = "https://build.shibboleth.net/nexus/content/repositories/releases/",
    )

  if "org_opensaml_xmltooling" not in excludes:
    native.maven_jar(
        name = "org_opensaml_xmltooling",
        artifact = "org.opensaml:xmltooling:jar:1.4.6",
        repository = "https://build.shibboleth.net/nexus/content/repositories/releases/",
    )

  if "commons_httpclient_commons_httpclient" not in excludes:
    native.maven_jar(
        name = "commons_httpclient_commons_httpclient",
        artifact = "commons-httpclient:commons-httpclient:jar:3.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "joda_time_joda_time" not in excludes:
    native.maven_jar(
        name = "joda_time_joda_time",
        artifact = "joda-time:joda-time:jar:2.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_slf4j_jcl_over_slf4j" not in excludes:
    native.maven_jar(
        name = "org_slf4j_jcl_over_slf4j",
        artifact = "org.slf4j:jcl-over-slf4j:jar:1.7.5",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_slf4j_jul_to_slf4j" not in excludes:
    native.maven_jar(
        name = "org_slf4j_jul_to_slf4j",
        artifact = "org.slf4j:jul-to-slf4j:jar:1.7.5",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_owasp_antisamy_antisamy" not in excludes:
    native.maven_jar(
        name = "org_owasp_antisamy_antisamy",
        artifact = "org.owasp.antisamy:antisamy:jar:1.5.7",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_xmlgraphics_batik_css" not in excludes:
    native.maven_jar(
        name = "org_apache_xmlgraphics_batik_css",
        artifact = "org.apache.xmlgraphics:batik-css:jar:1.9.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_xmlgraphics_batik_util" not in excludes:
    native.maven_jar(
        name = "org_apache_xmlgraphics_batik_util",
        artifact = "org.apache.xmlgraphics:batik-util:jar:1.9.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_xmlgraphics_batik_constants" not in excludes:
    native.maven_jar(
        name = "org_apache_xmlgraphics_batik_constants",
        artifact = "org.apache.xmlgraphics:batik-constants:jar:1.9.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_xmlgraphics_batik_i18n" not in excludes:
    native.maven_jar(
        name = "org_apache_xmlgraphics_batik_i18n",
        artifact = "org.apache.xmlgraphics:batik-i18n:jar:1.9.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_xmlgraphics_xmlgraphics_commons" not in excludes:
    native.maven_jar(
        name = "org_apache_xmlgraphics_xmlgraphics_commons",
        artifact = "org.apache.xmlgraphics:xmlgraphics-commons:jar:2.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "xml_apis_xml_apis_ext" not in excludes:
    native.maven_jar(
        name = "xml_apis_xml_apis_ext",
        artifact = "xml-apis:xml-apis-ext:jar:1.3.04",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_owasp_esapi_esapi" not in excludes:
    native.maven_jar(
        name = "org_owasp_esapi_esapi",
        artifact = "org.owasp.esapi:esapi:jar:2.1.0.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_configuration_commons_configuration" not in excludes:
    native.maven_jar(
        name = "commons_configuration_commons_configuration",
        artifact = "commons-configuration:commons-configuration:jar:1.10",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "xom_xom" not in excludes:
    native.maven_jar(
        name = "xom_xom",
        artifact = "xom:xom:jar:1.2.5",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_beanshell_bsh_core" not in excludes:
    native.maven_jar(
        name = "org_beanshell_bsh_core",
        artifact = "org.beanshell:bsh-core:jar:2.0b4",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_config" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_config",
        artifact = "org.springframework.security:spring-security-config:jar:4.2.4.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "xalan_xalan" not in excludes:
    native.maven_jar(
        name = "xalan_xalan",
        artifact = "xalan:xalan:jar:2.7.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "xalan_serializer" not in excludes:
    native.maven_jar(
        name = "xalan_serializer",
        artifact = "xalan:serializer:jar:2.7.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "xml_apis_xml_apis" not in excludes:
    native.maven_jar(
        name = "xml_apis_xml_apis",
        artifact = "xml-apis:xml-apis:jar:1.4.01",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_oauth_spring_security_oauth2" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_oauth_spring_security_oauth2",
        artifact = "org.springframework.security.oauth:spring-security-oauth2:jar:2.0.15.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_spring_webmvc" not in excludes:
    native.maven_jar(
        name = "org_springframework_spring_webmvc",
        artifact = "org.springframework:spring-webmvc:jar:4.0.9.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_bouncycastle_bcprov_jdk15on" not in excludes:
    native.maven_jar(
        name = "org_bouncycastle_bcprov_jdk15on",
        artifact = "org.bouncycastle:bcprov-jdk15on:jar:1.60",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_bouncycastle_bcpkix_jdk15on" not in excludes:
    native.maven_jar(
        name = "org_bouncycastle_bcpkix_jdk15on",
        artifact = "org.bouncycastle:bcpkix-jdk15on:jar:1.60",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_guava_guava" not in excludes:
    native.maven_jar(
        name = "com_google_guava_guava",
        artifact = "com.google.guava:guava:jar:24.1.1-jre",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_code_findbugs_jsr305" not in excludes:
    native.maven_jar(
        name = "com_google_code_findbugs_jsr305",
        artifact = "com.google.code.findbugs:jsr305:jar:1.3.9",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_checkerframework_checker_compat_qual" not in excludes:
    native.maven_jar(
        name = "org_checkerframework_checker_compat_qual",
        artifact = "org.checkerframework:checker-compat-qual:jar:2.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_errorprone_error_prone_annotations" not in excludes:
    native.maven_jar(
        name = "com_google_errorprone_error_prone_annotations",
        artifact = "com.google.errorprone:error_prone_annotations:jar:2.1.3",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_google_j2objc_j2objc_annotations" not in excludes:
    native.maven_jar(
        name = "com_google_j2objc_j2objc_annotations",
        artifact = "com.google.j2objc:j2objc-annotations:jar:1.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_codehaus_mojo_animal_sniffer_annotations" not in excludes:
    native.maven_jar(
        name = "org_codehaus_mojo_animal_sniffer_annotations",
        artifact = "org.codehaus.mojo:animal-sniffer-annotations:jar:1.14",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_aspectj_aspectjrt" not in excludes:
    native.maven_jar(
        name = "org_aspectj_aspectjrt",
        artifact = "org.aspectj:aspectjrt:jar:1.8.12",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_aspectj_aspectjweaver" not in excludes:
    native.maven_jar(
        name = "org_aspectj_aspectjweaver",
        artifact = "org.aspectj:aspectjweaver:jar:1.8.12",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_thymeleaf_thymeleaf_spring4" not in excludes:
    native.maven_jar(
        name = "org_thymeleaf_thymeleaf_spring4",
        artifact = "org.thymeleaf:thymeleaf-spring4:jar:3.0.6.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_thymeleaf_thymeleaf" not in excludes:
    native.maven_jar(
        name = "org_thymeleaf_thymeleaf",
        artifact = "org.thymeleaf:thymeleaf:jar:3.0.6.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_attoparser_attoparser" not in excludes:
    native.maven_jar(
        name = "org_attoparser_attoparser",
        artifact = "org.attoparser:attoparser:jar:2.0.4.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_unbescape_unbescape" not in excludes:
    native.maven_jar(
        name = "org_unbescape_unbescape",
        artifact = "org.unbescape:unbescape:jar:1.1.4.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "nz_net_ultraq_thymeleaf_thymeleaf_layout_dialect" not in excludes:
    native.maven_jar(
        name = "nz_net_ultraq_thymeleaf_thymeleaf_layout_dialect",
        artifact = "nz.net.ultraq.thymeleaf:thymeleaf-layout-dialect:jar:2.3.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "nz_net_ultraq_thymeleaf_thymeleaf_expression_processor" not in excludes:
    native.maven_jar(
        name = "nz_net_ultraq_thymeleaf_thymeleaf_expression_processor",
        artifact = "nz.net.ultraq.thymeleaf:thymeleaf-expression-processor:jar:1.1.3",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_codehaus_groovy_groovy" not in excludes:
    native.maven_jar(
        name = "org_codehaus_groovy_groovy",
        artifact = "org.codehaus.groovy:groovy:jar:2.4.13",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_thymeleaf_extras_thymeleaf_extras_springsecurity4" not in excludes:
    native.maven_jar(
        name = "org_thymeleaf_extras_thymeleaf_extras_springsecurity4",
        artifact = "org.thymeleaf.extras:thymeleaf-extras-springsecurity4:jar:3.0.2.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_unboundid_product_scim_scim_sdk" not in excludes:
    native.maven_jar(
        name = "com_unboundid_product_scim_scim_sdk",
        artifact = "com.unboundid.product.scim:scim-sdk:jar:1.8.18",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_unboundid_components_json" not in excludes:
    native.maven_jar(
        name = "com_unboundid_components_json",
        artifact = "com.unboundid.components:json:jar:1.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_jersey_connectors_jersey_apache_connector" not in excludes:
    native.maven_jar(
        name = "org_glassfish_jersey_connectors_jersey_apache_connector",
        artifact = "org.glassfish.jersey.connectors:jersey-apache-connector:jar:2.17",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_jersey_core_jersey_common" not in excludes:
    native.maven_jar(
        name = "org_glassfish_jersey_core_jersey_common",
        artifact = "org.glassfish.jersey.core:jersey-common:jar:2.17",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "javax_annotation_javax_annotation_api" not in excludes:
    native.maven_jar(
        name = "javax_annotation_javax_annotation_api",
        artifact = "javax.annotation:javax.annotation-api:jar:1.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_jersey_bundles_repackaged_jersey_guava" not in excludes:
    native.maven_jar(
        name = "org_glassfish_jersey_bundles_repackaged_jersey_guava",
        artifact = "org.glassfish.jersey.bundles.repackaged:jersey-guava:jar:2.17",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_hk2_hk2_api" not in excludes:
    native.maven_jar(
        name = "org_glassfish_hk2_hk2_api",
        artifact = "org.glassfish.hk2:hk2-api:jar:2.4.0-b10",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_hk2_hk2_utils" not in excludes:
    native.maven_jar(
        name = "org_glassfish_hk2_hk2_utils",
        artifact = "org.glassfish.hk2:hk2-utils:jar:2.4.0-b10",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_hk2_external_aopalliance_repackaged" not in excludes:
    native.maven_jar(
        name = "org_glassfish_hk2_external_aopalliance_repackaged",
        artifact = "org.glassfish.hk2.external:aopalliance-repackaged:jar:2.4.0-b10",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_hk2_external_javax_inject" not in excludes:
    native.maven_jar(
        name = "org_glassfish_hk2_external_javax_inject",
        artifact = "org.glassfish.hk2.external:javax.inject:jar:2.4.0-b10",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_hk2_hk2_locator" not in excludes:
    native.maven_jar(
        name = "org_glassfish_hk2_hk2_locator",
        artifact = "org.glassfish.hk2:hk2-locator:jar:2.4.0-b10",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_javassist_javassist" not in excludes:
    native.maven_jar(
        name = "org_javassist_javassist",
        artifact = "org.javassist:javassist:jar:3.18.1-GA",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_hk2_osgi_resource_locator" not in excludes:
    native.maven_jar(
        name = "org_glassfish_hk2_osgi_resource_locator",
        artifact = "org.glassfish.hk2:osgi-resource-locator:jar:1.0.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_glassfish_jersey_core_jersey_client" not in excludes:
    native.maven_jar(
        name = "org_glassfish_jersey_core_jersey_client",
        artifact = "org.glassfish.jersey.core:jersey-client:jar:2.17",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "javax_ws_rs_javax_ws_rs_api" not in excludes:
    native.maven_jar(
        name = "javax_ws_rs_javax_ws_rs_api",
        artifact = "javax.ws.rs:javax.ws.rs-api:jar:2.0.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_hibernate_hibernate_validator" not in excludes:
    native.maven_jar(
        name = "org_hibernate_hibernate_validator",
        artifact = "org.hibernate:hibernate-validator:jar:5.3.6.Final",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "javax_validation_validation_api" not in excludes:
    native.maven_jar(
        name = "javax_validation_validation_api",
        artifact = "javax.validation:validation-api:jar:1.1.0.Final",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_jboss_logging_jboss_logging" not in excludes:
    native.maven_jar(
        name = "org_jboss_logging_jboss_logging",
        artifact = "org.jboss.logging:jboss-logging:jar:3.3.0.Final",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_fasterxml_classmate" not in excludes:
    native.maven_jar(
        name = "com_fasterxml_classmate",
        artifact = "com.fasterxml:classmate:jar:1.3.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_flywaydb_flyway_core" not in excludes:
    native.maven_jar(
        name = "org_flywaydb_flyway_core",
        artifact = "org.flywaydb:flyway-core:jar:4.2.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_mariadb_jdbc_mariadb_java_client" not in excludes:
    native.maven_jar(
        name = "org_mariadb_jdbc_mariadb_java_client",
        artifact = "org.mariadb.jdbc:mariadb-java-client:jar:2.2.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_microsoft_sqlserver_mssql_jdbc" not in excludes:
    native.maven_jar(
        name = "com_microsoft_sqlserver_mssql_jdbc",
        artifact = "com.microsoft.sqlserver:mssql-jdbc:jar:6.2.2.jre8",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_hsqldb_hsqldb" not in excludes:
    native.maven_jar(
        name = "org_hsqldb_hsqldb",
        artifact = "org.hsqldb:hsqldb:jar:2.3.1",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_yaml_snakeyaml" not in excludes:
    native.maven_jar(
        name = "org_yaml_snakeyaml",
        artifact = "org.yaml:snakeyaml:jar:1.18",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_security_spring_security_ldap" not in excludes:
    native.maven_jar(
        name = "org_springframework_security_spring_security_ldap",
        artifact = "org.springframework.security:spring-security-ldap:jar:4.2.7.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_ldap_spring_ldap_core" not in excludes:
    native.maven_jar(
        name = "org_springframework_ldap_spring_ldap_core",
        artifact = "org.springframework.ldap:spring-ldap-core:jar:2.3.2.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_springframework_ldap_spring_ldap_core_tiger" not in excludes:
    native.maven_jar(
        name = "org_springframework_ldap_spring_ldap_core_tiger",
        artifact = "org.springframework.ldap:spring-ldap-core-tiger:jar:2.3.2.RELEASE",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_directory_api_api_ldap_model" not in excludes:
    native.maven_jar(
        name = "org_apache_directory_api_api_ldap_model",
        artifact = "org.apache.directory.api:api-ldap-model:jar:1.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_directory_api_api_util" not in excludes:
    native.maven_jar(
        name = "org_apache_directory_api_api_util",
        artifact = "org.apache.directory.api:api-util:jar:1.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_directory_api_api_asn1_api" not in excludes:
    native.maven_jar(
        name = "org_apache_directory_api_api_asn1_api",
        artifact = "org.apache.directory.api:api-asn1-api:jar:1.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_directory_api_api_asn1_ber" not in excludes:
    native.maven_jar(
        name = "org_apache_directory_api_api_asn1_ber",
        artifact = "org.apache.directory.api:api-asn1-ber:jar:1.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_directory_api_api_i18n" not in excludes:
    native.maven_jar(
        name = "org_apache_directory_api_api_i18n",
        artifact = "org.apache.directory.api:api-i18n:jar:1.0.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_mina_mina_core" not in excludes:
    native.maven_jar(
        name = "org_apache_mina_mina_core",
        artifact = "org.apache.mina:mina-core:jar:2.0.16",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_apache_servicemix_bundles_org_apache_servicemix_bundles_antlr" not in excludes:
    native.maven_jar(
        name = "org_apache_servicemix_bundles_org_apache_servicemix_bundles_antlr",
        artifact = "org.apache.servicemix.bundles:org.apache.servicemix.bundles.antlr:jar:2.7.7_5",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_lang_commons_lang" not in excludes:
    native.maven_jar(
        name = "commons_lang_commons_lang",
        artifact = "commons-lang:commons-lang:jar:2.6",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "commons_collections_commons_collections" not in excludes:
    native.maven_jar(
        name = "commons_collections_commons_collections",
        artifact = "commons-collections:commons-collections:jar:3.2.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_passay_passay" not in excludes:
    native.maven_jar(
        name = "org_passay_passay",
        artifact = "org.passay:passay:jar:1.2.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_cryptacular_cryptacular" not in excludes:
    native.maven_jar(
        name = "org_cryptacular_cryptacular",
        artifact = "org.cryptacular:cryptacular:jar:1.2.0",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "com_warrenstrange_googleauth" not in excludes:
    native.maven_jar(
        name = "com_warrenstrange_googleauth",
        artifact = "com.warrenstrange:googleauth:jar:1.1.2",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "org_slf4j_slf4j_log4j12" not in excludes:
    native.maven_jar(
        name = "org_slf4j_slf4j_log4j12",
        artifact = "org.slf4j:slf4j-log4j12:jar:1.7.25",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "log4j_log4j" not in excludes:
    native.maven_jar(
        name = "log4j_log4j",
        artifact = "log4j:log4j:jar:1.2.17",
        repository = "https://repo1.maven.org/maven2/",
    )

  if "javax_servlet_javax_servlet_api" not in excludes:
    native.maven_jar(
        name = "javax_servlet_javax_servlet_api",
        artifact = "javax.servlet:javax.servlet-api:jar:3.1.0",
        repository = "https://repo1.maven.org/maven2/",
    )

def generated_java_libraries():
  excludes = native.existing_rules().keys()

  if "org_apache_tomcat_tomcat_jdbc" not in excludes:
    native.java_library(
        name = "org_apache_tomcat_tomcat_jdbc",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_tomcat_tomcat_jdbc//jar"],
        runtime_deps = [
            ":org_apache_tomcat_tomcat_juli",
        ],
    )

  if "org_apache_tomcat_tomcat_juli" not in excludes:
    native.java_library(
        name = "org_apache_tomcat_tomcat_juli",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_tomcat_tomcat_juli//jar"],
    )

  if "javax_mail_mail" not in excludes:
    native.java_library(
        name = "javax_mail_mail",
        visibility = ["//visibility:public"],
        exports = ["@javax_mail_mail//jar"],
        runtime_deps = [
            ":javax_activation_activation",
        ],
    )

  if "javax_activation_activation" not in excludes:
    native.java_library(
        name = "javax_activation_activation",
        visibility = ["//visibility:public"],
        exports = ["@javax_activation_activation//jar"],
    )

  if "commons_logging_commons_logging" not in excludes:
    native.java_library(
        name = "commons_logging_commons_logging",
        visibility = ["//visibility:public"],
        exports = ["@commons_logging_commons_logging//jar"],
    )

  if "com_jayway_jsonpath_json_path" not in excludes:
    native.java_library(
        name = "com_jayway_jsonpath_json_path",
        visibility = ["//visibility:public"],
        exports = ["@com_jayway_jsonpath_json_path//jar"],
        runtime_deps = [
            ":net_minidev_json_smart",
            ":org_slf4j_slf4j_api",
        ],
    )

  if "net_minidev_json_smart" not in excludes:
    native.java_library(
        name = "net_minidev_json_smart",
        visibility = ["//visibility:public"],
        exports = ["@net_minidev_json_smart//jar"],
        runtime_deps = [
            ":net_minidev_accessors_smart",
        ],
    )

  if "net_minidev_accessors_smart" not in excludes:
    native.java_library(
        name = "net_minidev_accessors_smart",
        visibility = ["//visibility:public"],
        exports = ["@net_minidev_accessors_smart//jar"],
        runtime_deps = [
            ":org_ow2_asm_asm",
        ],
    )

  if "org_ow2_asm_asm" not in excludes:
    native.java_library(
        name = "org_ow2_asm_asm",
        visibility = ["//visibility:public"],
        exports = ["@org_ow2_asm_asm//jar"],
    )

  if "org_slf4j_slf4j_api" not in excludes:
    native.java_library(
        name = "org_slf4j_slf4j_api",
        visibility = ["//visibility:public"],
        exports = ["@org_slf4j_slf4j_api//jar"],
    )

  if "com_google_zxing_javase" not in excludes:
    native.java_library(
        name = "com_google_zxing_javase",
        visibility = ["//visibility:public"],
        exports = ["@com_google_zxing_javase//jar"],
        runtime_deps = [
            ":com_google_zxing_core",
            ":com_beust_jcommander",
            ":com_github_jai_imageio_jai_imageio_core",
        ],
    )

  if "com_google_zxing_core" not in excludes:
    native.java_library(
        name = "com_google_zxing_core",
        visibility = ["//visibility:public"],
        exports = ["@com_google_zxing_core//jar"],
    )

  if "com_beust_jcommander" not in excludes:
    native.java_library(
        name = "com_beust_jcommander",
        visibility = ["//visibility:public"],
        exports = ["@com_beust_jcommander//jar"],
    )

  if "com_github_jai_imageio_jai_imageio_core" not in excludes:
    native.java_library(
        name = "com_github_jai_imageio_jai_imageio_core",
        visibility = ["//visibility:public"],
        exports = ["@com_github_jai_imageio_jai_imageio_core//jar"],
    )

  if "org_springframework_spring_beans" not in excludes:
    native.java_library(
        name = "org_springframework_spring_beans",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_beans//jar"],
        runtime_deps = [
            ":org_springframework_spring_core",
        ],
    )

  if "org_springframework_spring_core" not in excludes:
    native.java_library(
        name = "org_springframework_spring_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_core//jar"],
    )

  if "org_springframework_spring_context" not in excludes:
    native.java_library(
        name = "org_springframework_spring_context",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_context//jar"],
        runtime_deps = [
            ":org_springframework_spring_aop",
            ":org_springframework_spring_expression",
        ],
    )

  if "org_springframework_spring_aop" not in excludes:
    native.java_library(
        name = "org_springframework_spring_aop",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_aop//jar"],
    )

  if "org_springframework_spring_expression" not in excludes:
    native.java_library(
        name = "org_springframework_spring_expression",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_expression//jar"],
    )

  if "org_springframework_spring_tx" not in excludes:
    native.java_library(
        name = "org_springframework_spring_tx",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_tx//jar"],
    )

  if "org_springframework_spring_jdbc" not in excludes:
    native.java_library(
        name = "org_springframework_spring_jdbc",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_jdbc//jar"],
    )

  if "org_springframework_spring_web" not in excludes:
    native.java_library(
        name = "org_springframework_spring_web",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_web//jar"],
    )

  if "org_springframework_spring_context_support" not in excludes:
    native.java_library(
        name = "org_springframework_spring_context_support",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_context_support//jar"],
    )

  if "org_springframework_security_spring_security_core" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_core//jar"],
        runtime_deps = [
            ":aopalliance_aopalliance",
        ],
    )

  if "aopalliance_aopalliance" not in excludes:
    native.java_library(
        name = "aopalliance_aopalliance",
        visibility = ["//visibility:public"],
        exports = ["@aopalliance_aopalliance//jar"],
    )

  if "org_springframework_security_spring_security_jwt" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_jwt",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_jwt//jar"],
    )

  if "org_apache_httpcomponents_httpclient" not in excludes:
    native.java_library(
        name = "org_apache_httpcomponents_httpclient",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_httpcomponents_httpclient//jar"],
        runtime_deps = [
            ":org_apache_httpcomponents_httpcore",
            ":commons_codec_commons_codec",
        ],
    )

  if "org_apache_httpcomponents_httpcore" not in excludes:
    native.java_library(
        name = "org_apache_httpcomponents_httpcore",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_httpcomponents_httpcore//jar"],
    )

  if "commons_codec_commons_codec" not in excludes:
    native.java_library(
        name = "commons_codec_commons_codec",
        visibility = ["//visibility:public"],
        exports = ["@commons_codec_commons_codec//jar"],
    )

  if "org_springframework_security_spring_security_openid" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_openid",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_openid//jar"],
        runtime_deps = [
            ":com_google_inject_guice",
            ":org_openid4java_openid4java_nodeps",
            ":net_sourceforge_nekohtml_nekohtml",
        ],
    )

  if "com_google_inject_guice" not in excludes:
    native.java_library(
        name = "com_google_inject_guice",
        visibility = ["//visibility:public"],
        exports = ["@com_google_inject_guice//jar"],
    )

  if "org_openid4java_openid4java_nodeps" not in excludes:
    native.java_library(
        name = "org_openid4java_openid4java_nodeps",
        visibility = ["//visibility:public"],
        exports = ["@org_openid4java_openid4java_nodeps//jar"],
        runtime_deps = [
            ":net_jcip_jcip_annotations",
        ],
    )

  if "net_jcip_jcip_annotations" not in excludes:
    native.java_library(
        name = "net_jcip_jcip_annotations",
        visibility = ["//visibility:public"],
        exports = ["@net_jcip_jcip_annotations//jar"],
    )

  if "net_sourceforge_nekohtml_nekohtml" not in excludes:
    native.java_library(
        name = "net_sourceforge_nekohtml_nekohtml",
        visibility = ["//visibility:public"],
        exports = ["@net_sourceforge_nekohtml_nekohtml//jar"],
        runtime_deps = [
            ":xerces_xercesImpl",
        ],
    )

  if "xerces_xercesImpl" not in excludes:
    native.java_library(
        name = "xerces_xercesImpl",
        visibility = ["//visibility:public"],
        exports = ["@xerces_xercesImpl//jar"],
    )

  if "org_springframework_security_spring_security_web" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_web",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_web//jar"],
    )

  if "org_springframework_security_extensions_spring_security_saml2_core" not in excludes:
    native.java_library(
        name = "org_springframework_security_extensions_spring_security_saml2_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_extensions_spring_security_saml2_core//jar"],
        runtime_deps = [
            ":ca_juliusdavies_not_yet_commons_ssl",
            ":commons_beanutils_commons_beanutils",
            ":commons_fileupload_commons_fileupload",
            ":org_apache_santuario_xmlsec",
            ":org_apache_velocity_velocity_engine_core",
            ":org_opensaml_opensaml",
            ":org_owasp_antisamy_antisamy",
            ":org_owasp_esapi_esapi",
            ":org_springframework_security_spring_security_config",
            ":xalan_xalan",
            ":xml_apis_xml_apis",
        ],
    )

  if "ca_juliusdavies_not_yet_commons_ssl" not in excludes:
    native.java_library(
        name = "ca_juliusdavies_not_yet_commons_ssl",
        visibility = ["//visibility:public"],
        exports = ["@ca_juliusdavies_not_yet_commons_ssl//jar"],
    )

  if "commons_beanutils_commons_beanutils" not in excludes:
    native.java_library(
        name = "commons_beanutils_commons_beanutils",
        visibility = ["//visibility:public"],
        exports = ["@commons_beanutils_commons_beanutils//jar"],
    )

  if "commons_fileupload_commons_fileupload" not in excludes:
    native.java_library(
        name = "commons_fileupload_commons_fileupload",
        visibility = ["//visibility:public"],
        exports = ["@commons_fileupload_commons_fileupload//jar"],
        runtime_deps = [
            ":commons_io_commons_io",
        ],
    )

  if "commons_io_commons_io" not in excludes:
    native.java_library(
        name = "commons_io_commons_io",
        visibility = ["//visibility:public"],
        exports = ["@commons_io_commons_io//jar"],
    )

  if "org_apache_santuario_xmlsec" not in excludes:
    native.java_library(
        name = "org_apache_santuario_xmlsec",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_santuario_xmlsec//jar"],
    )

  if "org_apache_velocity_velocity_engine_core" not in excludes:
    native.java_library(
        name = "org_apache_velocity_velocity_engine_core",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_velocity_velocity_engine_core//jar"],
        runtime_deps = [
            ":org_apache_commons_commons_lang3",
        ],
    )

  if "org_apache_commons_commons_lang3" not in excludes:
    native.java_library(
        name = "org_apache_commons_commons_lang3",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_commons_commons_lang3//jar"],
    )

  if "org_opensaml_opensaml" not in excludes:
    native.java_library(
        name = "org_opensaml_opensaml",
        visibility = ["//visibility:public"],
        exports = ["@org_opensaml_opensaml//jar"],
        runtime_deps = [
            ":org_opensaml_openws",
            ":joda_time_joda_time",
            ":org_slf4j_jcl_over_slf4j",
            ":org_slf4j_jul_to_slf4j",
        ],
    )

  if "org_opensaml_openws" not in excludes:
    native.java_library(
        name = "org_opensaml_openws",
        visibility = ["//visibility:public"],
        exports = ["@org_opensaml_openws//jar"],
        runtime_deps = [
            ":org_opensaml_xmltooling",
            ":commons_httpclient_commons_httpclient",
        ],
    )

  if "org_opensaml_xmltooling" not in excludes:
    native.java_library(
        name = "org_opensaml_xmltooling",
        visibility = ["//visibility:public"],
        exports = ["@org_opensaml_xmltooling//jar"],
    )

  if "commons_httpclient_commons_httpclient" not in excludes:
    native.java_library(
        name = "commons_httpclient_commons_httpclient",
        visibility = ["//visibility:public"],
        exports = ["@commons_httpclient_commons_httpclient//jar"],
    )

  if "joda_time_joda_time" not in excludes:
    native.java_library(
        name = "joda_time_joda_time",
        visibility = ["//visibility:public"],
        exports = ["@joda_time_joda_time//jar"],
    )

  if "org_slf4j_jcl_over_slf4j" not in excludes:
    native.java_library(
        name = "org_slf4j_jcl_over_slf4j",
        visibility = ["//visibility:public"],
        exports = ["@org_slf4j_jcl_over_slf4j//jar"],
    )

  if "org_slf4j_jul_to_slf4j" not in excludes:
    native.java_library(
        name = "org_slf4j_jul_to_slf4j",
        visibility = ["//visibility:public"],
        exports = ["@org_slf4j_jul_to_slf4j//jar"],
    )

  if "org_owasp_antisamy_antisamy" not in excludes:
    native.java_library(
        name = "org_owasp_antisamy_antisamy",
        visibility = ["//visibility:public"],
        exports = ["@org_owasp_antisamy_antisamy//jar"],
        runtime_deps = [
            ":org_apache_xmlgraphics_batik_css",
        ],
    )

  if "org_apache_xmlgraphics_batik_css" not in excludes:
    native.java_library(
        name = "org_apache_xmlgraphics_batik_css",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_xmlgraphics_batik_css//jar"],
        runtime_deps = [
            ":org_apache_xmlgraphics_batik_util",
            ":org_apache_xmlgraphics_xmlgraphics_commons",
            ":xml_apis_xml_apis_ext",
        ],
    )

  if "org_apache_xmlgraphics_batik_util" not in excludes:
    native.java_library(
        name = "org_apache_xmlgraphics_batik_util",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_xmlgraphics_batik_util//jar"],
        runtime_deps = [
            ":org_apache_xmlgraphics_batik_constants",
            ":org_apache_xmlgraphics_batik_i18n",
        ],
    )

  if "org_apache_xmlgraphics_batik_constants" not in excludes:
    native.java_library(
        name = "org_apache_xmlgraphics_batik_constants",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_xmlgraphics_batik_constants//jar"],
    )

  if "org_apache_xmlgraphics_batik_i18n" not in excludes:
    native.java_library(
        name = "org_apache_xmlgraphics_batik_i18n",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_xmlgraphics_batik_i18n//jar"],
    )

  if "org_apache_xmlgraphics_xmlgraphics_commons" not in excludes:
    native.java_library(
        name = "org_apache_xmlgraphics_xmlgraphics_commons",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_xmlgraphics_xmlgraphics_commons//jar"],
    )

  if "xml_apis_xml_apis_ext" not in excludes:
    native.java_library(
        name = "xml_apis_xml_apis_ext",
        visibility = ["//visibility:public"],
        exports = ["@xml_apis_xml_apis_ext//jar"],
    )

  if "org_owasp_esapi_esapi" not in excludes:
    native.java_library(
        name = "org_owasp_esapi_esapi",
        visibility = ["//visibility:public"],
        exports = ["@org_owasp_esapi_esapi//jar"],
        runtime_deps = [
            ":commons_configuration_commons_configuration",
            ":xom_xom",
            ":org_beanshell_bsh_core",
        ],
    )

  if "commons_configuration_commons_configuration" not in excludes:
    native.java_library(
        name = "commons_configuration_commons_configuration",
        visibility = ["//visibility:public"],
        exports = ["@commons_configuration_commons_configuration//jar"],
    )

  if "xom_xom" not in excludes:
    native.java_library(
        name = "xom_xom",
        visibility = ["//visibility:public"],
        exports = ["@xom_xom//jar"],
    )

  if "org_beanshell_bsh_core" not in excludes:
    native.java_library(
        name = "org_beanshell_bsh_core",
        visibility = ["//visibility:public"],
        exports = ["@org_beanshell_bsh_core//jar"],
    )

  if "org_springframework_security_spring_security_config" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_config",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_config//jar"],
    )

  if "xalan_xalan" not in excludes:
    native.java_library(
        name = "xalan_xalan",
        visibility = ["//visibility:public"],
        exports = ["@xalan_xalan//jar"],
        runtime_deps = [
            ":xalan_serializer",
        ],
    )

  if "xalan_serializer" not in excludes:
    native.java_library(
        name = "xalan_serializer",
        visibility = ["//visibility:public"],
        exports = ["@xalan_serializer//jar"],
    )

  if "xml_apis_xml_apis" not in excludes:
    native.java_library(
        name = "xml_apis_xml_apis",
        visibility = ["//visibility:public"],
        exports = ["@xml_apis_xml_apis//jar"],
    )

  if "org_springframework_security_oauth_spring_security_oauth2" not in excludes:
    native.java_library(
        name = "org_springframework_security_oauth_spring_security_oauth2",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_oauth_spring_security_oauth2//jar"],
        runtime_deps = [
            ":org_springframework_spring_webmvc",
        ],
    )

  if "org_springframework_spring_webmvc" not in excludes:
    native.java_library(
        name = "org_springframework_spring_webmvc",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_spring_webmvc//jar"],
    )

  if "org_bouncycastle_bcprov_jdk15on" not in excludes:
    native.java_library(
        name = "org_bouncycastle_bcprov_jdk15on",
        visibility = ["//visibility:public"],
        exports = ["@org_bouncycastle_bcprov_jdk15on//jar"],
    )

  if "org_bouncycastle_bcpkix_jdk15on" not in excludes:
    native.java_library(
        name = "org_bouncycastle_bcpkix_jdk15on",
        visibility = ["//visibility:public"],
        exports = ["@org_bouncycastle_bcpkix_jdk15on//jar"],
    )

  if "com_google_guava_guava" not in excludes:
    native.java_library(
        name = "com_google_guava_guava",
        visibility = ["//visibility:public"],
        exports = ["@com_google_guava_guava//jar"],
        runtime_deps = [
            ":com_google_code_findbugs_jsr305",
            ":org_checkerframework_checker_compat_qual",
            ":com_google_errorprone_error_prone_annotations",
            ":com_google_j2objc_j2objc_annotations",
            ":org_codehaus_mojo_animal_sniffer_annotations",
        ],
    )

  if "com_google_code_findbugs_jsr305" not in excludes:
    native.java_library(
        name = "com_google_code_findbugs_jsr305",
        visibility = ["//visibility:public"],
        exports = ["@com_google_code_findbugs_jsr305//jar"],
    )

  if "org_checkerframework_checker_compat_qual" not in excludes:
    native.java_library(
        name = "org_checkerframework_checker_compat_qual",
        visibility = ["//visibility:public"],
        exports = ["@org_checkerframework_checker_compat_qual//jar"],
    )

  if "com_google_errorprone_error_prone_annotations" not in excludes:
    native.java_library(
        name = "com_google_errorprone_error_prone_annotations",
        visibility = ["//visibility:public"],
        exports = ["@com_google_errorprone_error_prone_annotations//jar"],
    )

  if "com_google_j2objc_j2objc_annotations" not in excludes:
    native.java_library(
        name = "com_google_j2objc_j2objc_annotations",
        visibility = ["//visibility:public"],
        exports = ["@com_google_j2objc_j2objc_annotations//jar"],
    )

  if "org_codehaus_mojo_animal_sniffer_annotations" not in excludes:
    native.java_library(
        name = "org_codehaus_mojo_animal_sniffer_annotations",
        visibility = ["//visibility:public"],
        exports = ["@org_codehaus_mojo_animal_sniffer_annotations//jar"],
    )

  if "org_aspectj_aspectjrt" not in excludes:
    native.java_library(
        name = "org_aspectj_aspectjrt",
        visibility = ["//visibility:public"],
        exports = ["@org_aspectj_aspectjrt//jar"],
    )

  if "org_aspectj_aspectjweaver" not in excludes:
    native.java_library(
        name = "org_aspectj_aspectjweaver",
        visibility = ["//visibility:public"],
        exports = ["@org_aspectj_aspectjweaver//jar"],
    )

  if "org_thymeleaf_thymeleaf_spring4" not in excludes:
    native.java_library(
        name = "org_thymeleaf_thymeleaf_spring4",
        visibility = ["//visibility:public"],
        exports = ["@org_thymeleaf_thymeleaf_spring4//jar"],
        runtime_deps = [
            ":org_thymeleaf_thymeleaf",
        ],
    )

  if "org_thymeleaf_thymeleaf" not in excludes:
    native.java_library(
        name = "org_thymeleaf_thymeleaf",
        visibility = ["//visibility:public"],
        exports = ["@org_thymeleaf_thymeleaf//jar"],
        runtime_deps = [
            ":org_attoparser_attoparser",
            ":org_unbescape_unbescape",
        ],
    )

  if "org_attoparser_attoparser" not in excludes:
    native.java_library(
        name = "org_attoparser_attoparser",
        visibility = ["//visibility:public"],
        exports = ["@org_attoparser_attoparser//jar"],
    )

  if "org_unbescape_unbescape" not in excludes:
    native.java_library(
        name = "org_unbescape_unbescape",
        visibility = ["//visibility:public"],
        exports = ["@org_unbescape_unbescape//jar"],
    )

  if "nz_net_ultraq_thymeleaf_thymeleaf_layout_dialect" not in excludes:
    native.java_library(
        name = "nz_net_ultraq_thymeleaf_thymeleaf_layout_dialect",
        visibility = ["//visibility:public"],
        exports = ["@nz_net_ultraq_thymeleaf_thymeleaf_layout_dialect//jar"],
        runtime_deps = [
            ":nz_net_ultraq_thymeleaf_thymeleaf_expression_processor",
            ":org_codehaus_groovy_groovy",
        ],
    )

  if "nz_net_ultraq_thymeleaf_thymeleaf_expression_processor" not in excludes:
    native.java_library(
        name = "nz_net_ultraq_thymeleaf_thymeleaf_expression_processor",
        visibility = ["//visibility:public"],
        exports = ["@nz_net_ultraq_thymeleaf_thymeleaf_expression_processor//jar"],
    )

  if "org_codehaus_groovy_groovy" not in excludes:
    native.java_library(
        name = "org_codehaus_groovy_groovy",
        visibility = ["//visibility:public"],
        exports = ["@org_codehaus_groovy_groovy//jar"],
    )

  if "org_thymeleaf_extras_thymeleaf_extras_springsecurity4" not in excludes:
    native.java_library(
        name = "org_thymeleaf_extras_thymeleaf_extras_springsecurity4",
        visibility = ["//visibility:public"],
        exports = ["@org_thymeleaf_extras_thymeleaf_extras_springsecurity4//jar"],
    )

  if "com_unboundid_product_scim_scim_sdk" not in excludes:
    native.java_library(
        name = "com_unboundid_product_scim_scim_sdk",
        visibility = ["//visibility:public"],
        exports = ["@com_unboundid_product_scim_scim_sdk//jar"],
        runtime_deps = [
            ":com_unboundid_components_json",
            ":org_glassfish_jersey_connectors_jersey_apache_connector",
        ],
    )

  if "com_unboundid_components_json" not in excludes:
    native.java_library(
        name = "com_unboundid_components_json",
        visibility = ["//visibility:public"],
        exports = ["@com_unboundid_components_json//jar"],
    )

  if "org_glassfish_jersey_connectors_jersey_apache_connector" not in excludes:
    native.java_library(
        name = "org_glassfish_jersey_connectors_jersey_apache_connector",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_jersey_connectors_jersey_apache_connector//jar"],
        runtime_deps = [
            ":org_glassfish_jersey_core_jersey_common",
            ":org_glassfish_jersey_core_jersey_client",
            ":javax_ws_rs_javax_ws_rs_api",
        ],
    )

  if "org_glassfish_jersey_core_jersey_common" not in excludes:
    native.java_library(
        name = "org_glassfish_jersey_core_jersey_common",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_jersey_core_jersey_common//jar"],
        runtime_deps = [
            ":javax_annotation_javax_annotation_api",
            ":org_glassfish_jersey_bundles_repackaged_jersey_guava",
            ":org_glassfish_hk2_hk2_api",
            ":org_glassfish_hk2_external_javax_inject",
            ":org_glassfish_hk2_hk2_locator",
            ":org_glassfish_hk2_osgi_resource_locator",
        ],
    )

  if "javax_annotation_javax_annotation_api" not in excludes:
    native.java_library(
        name = "javax_annotation_javax_annotation_api",
        visibility = ["//visibility:public"],
        exports = ["@javax_annotation_javax_annotation_api//jar"],
    )

  if "org_glassfish_jersey_bundles_repackaged_jersey_guava" not in excludes:
    native.java_library(
        name = "org_glassfish_jersey_bundles_repackaged_jersey_guava",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_jersey_bundles_repackaged_jersey_guava//jar"],
    )

  if "org_glassfish_hk2_hk2_api" not in excludes:
    native.java_library(
        name = "org_glassfish_hk2_hk2_api",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_hk2_hk2_api//jar"],
        runtime_deps = [
            ":org_glassfish_hk2_hk2_utils",
            ":org_glassfish_hk2_external_aopalliance_repackaged",
        ],
    )

  if "org_glassfish_hk2_hk2_utils" not in excludes:
    native.java_library(
        name = "org_glassfish_hk2_hk2_utils",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_hk2_hk2_utils//jar"],
    )

  if "org_glassfish_hk2_external_aopalliance_repackaged" not in excludes:
    native.java_library(
        name = "org_glassfish_hk2_external_aopalliance_repackaged",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_hk2_external_aopalliance_repackaged//jar"],
    )

  if "org_glassfish_hk2_external_javax_inject" not in excludes:
    native.java_library(
        name = "org_glassfish_hk2_external_javax_inject",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_hk2_external_javax_inject//jar"],
    )

  if "org_glassfish_hk2_hk2_locator" not in excludes:
    native.java_library(
        name = "org_glassfish_hk2_hk2_locator",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_hk2_hk2_locator//jar"],
        runtime_deps = [
            ":org_javassist_javassist",
        ],
    )

  if "org_javassist_javassist" not in excludes:
    native.java_library(
        name = "org_javassist_javassist",
        visibility = ["//visibility:public"],
        exports = ["@org_javassist_javassist//jar"],
    )

  if "org_glassfish_hk2_osgi_resource_locator" not in excludes:
    native.java_library(
        name = "org_glassfish_hk2_osgi_resource_locator",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_hk2_osgi_resource_locator//jar"],
    )

  if "org_glassfish_jersey_core_jersey_client" not in excludes:
    native.java_library(
        name = "org_glassfish_jersey_core_jersey_client",
        visibility = ["//visibility:public"],
        exports = ["@org_glassfish_jersey_core_jersey_client//jar"],
    )

  if "javax_ws_rs_javax_ws_rs_api" not in excludes:
    native.java_library(
        name = "javax_ws_rs_javax_ws_rs_api",
        visibility = ["//visibility:public"],
        exports = ["@javax_ws_rs_javax_ws_rs_api//jar"],
    )

  if "org_hibernate_hibernate_validator" not in excludes:
    native.java_library(
        name = "org_hibernate_hibernate_validator",
        visibility = ["//visibility:public"],
        exports = ["@org_hibernate_hibernate_validator//jar"],
        runtime_deps = [
            ":javax_validation_validation_api",
            ":org_jboss_logging_jboss_logging",
            ":com_fasterxml_classmate",
        ],
    )

  if "javax_validation_validation_api" not in excludes:
    native.java_library(
        name = "javax_validation_validation_api",
        visibility = ["//visibility:public"],
        exports = ["@javax_validation_validation_api//jar"],
    )

  if "org_jboss_logging_jboss_logging" not in excludes:
    native.java_library(
        name = "org_jboss_logging_jboss_logging",
        visibility = ["//visibility:public"],
        exports = ["@org_jboss_logging_jboss_logging//jar"],
    )

  if "com_fasterxml_classmate" not in excludes:
    native.java_library(
        name = "com_fasterxml_classmate",
        visibility = ["//visibility:public"],
        exports = ["@com_fasterxml_classmate//jar"],
    )

  if "org_flywaydb_flyway_core" not in excludes:
    native.java_library(
        name = "org_flywaydb_flyway_core",
        visibility = ["//visibility:public"],
        exports = ["@org_flywaydb_flyway_core//jar"],
    )

  if "org_mariadb_jdbc_mariadb_java_client" not in excludes:
    native.java_library(
        name = "org_mariadb_jdbc_mariadb_java_client",
        visibility = ["//visibility:public"],
        exports = ["@org_mariadb_jdbc_mariadb_java_client//jar"],
    )

  if "com_microsoft_sqlserver_mssql_jdbc" not in excludes:
    native.java_library(
        name = "com_microsoft_sqlserver_mssql_jdbc",
        visibility = ["//visibility:public"],
        exports = ["@com_microsoft_sqlserver_mssql_jdbc//jar"],
    )

  if "org_hsqldb_hsqldb" not in excludes:
    native.java_library(
        name = "org_hsqldb_hsqldb",
        visibility = ["//visibility:public"],
        exports = ["@org_hsqldb_hsqldb//jar"],
    )

  if "org_yaml_snakeyaml" not in excludes:
    native.java_library(
        name = "org_yaml_snakeyaml",
        visibility = ["//visibility:public"],
        exports = ["@org_yaml_snakeyaml//jar"],
    )

  if "org_springframework_security_spring_security_ldap" not in excludes:
    native.java_library(
        name = "org_springframework_security_spring_security_ldap",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_security_spring_security_ldap//jar"],
    )

  if "org_springframework_ldap_spring_ldap_core" not in excludes:
    native.java_library(
        name = "org_springframework_ldap_spring_ldap_core",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_ldap_spring_ldap_core//jar"],
    )

  if "org_springframework_ldap_spring_ldap_core_tiger" not in excludes:
    native.java_library(
        name = "org_springframework_ldap_spring_ldap_core_tiger",
        visibility = ["//visibility:public"],
        exports = ["@org_springframework_ldap_spring_ldap_core_tiger//jar"],
    )

  if "org_apache_directory_api_api_ldap_model" not in excludes:
    native.java_library(
        name = "org_apache_directory_api_api_ldap_model",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_directory_api_api_ldap_model//jar"],
        runtime_deps = [
            ":org_apache_directory_api_api_util",
            ":org_apache_directory_api_api_asn1_api",
            ":org_apache_directory_api_api_asn1_ber",
            ":org_apache_directory_api_api_i18n",
            ":org_apache_mina_mina_core",
            ":org_apache_servicemix_bundles_org_apache_servicemix_bundles_antlr",
            ":commons_lang_commons_lang",
            ":commons_collections_commons_collections",
        ],
    )

  if "org_apache_directory_api_api_util" not in excludes:
    native.java_library(
        name = "org_apache_directory_api_api_util",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_directory_api_api_util//jar"],
    )

  if "org_apache_directory_api_api_asn1_api" not in excludes:
    native.java_library(
        name = "org_apache_directory_api_api_asn1_api",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_directory_api_api_asn1_api//jar"],
    )

  if "org_apache_directory_api_api_asn1_ber" not in excludes:
    native.java_library(
        name = "org_apache_directory_api_api_asn1_ber",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_directory_api_api_asn1_ber//jar"],
    )

  if "org_apache_directory_api_api_i18n" not in excludes:
    native.java_library(
        name = "org_apache_directory_api_api_i18n",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_directory_api_api_i18n//jar"],
    )

  if "org_apache_mina_mina_core" not in excludes:
    native.java_library(
        name = "org_apache_mina_mina_core",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_mina_mina_core//jar"],
    )

  if "org_apache_servicemix_bundles_org_apache_servicemix_bundles_antlr" not in excludes:
    native.java_library(
        name = "org_apache_servicemix_bundles_org_apache_servicemix_bundles_antlr",
        visibility = ["//visibility:public"],
        exports = ["@org_apache_servicemix_bundles_org_apache_servicemix_bundles_antlr//jar"],
    )

  if "commons_lang_commons_lang" not in excludes:
    native.java_library(
        name = "commons_lang_commons_lang",
        visibility = ["//visibility:public"],
        exports = ["@commons_lang_commons_lang//jar"],
    )

  if "commons_collections_commons_collections" not in excludes:
    native.java_library(
        name = "commons_collections_commons_collections",
        visibility = ["//visibility:public"],
        exports = ["@commons_collections_commons_collections//jar"],
    )

  if "org_passay_passay" not in excludes:
    native.java_library(
        name = "org_passay_passay",
        visibility = ["//visibility:public"],
        exports = ["@org_passay_passay//jar"],
        runtime_deps = [
            ":org_cryptacular_cryptacular",
        ],
    )

  if "org_cryptacular_cryptacular" not in excludes:
    native.java_library(
        name = "org_cryptacular_cryptacular",
        visibility = ["//visibility:public"],
        exports = ["@org_cryptacular_cryptacular//jar"],
    )

  if "com_warrenstrange_googleauth" not in excludes:
    native.java_library(
        name = "com_warrenstrange_googleauth",
        visibility = ["//visibility:public"],
        exports = ["@com_warrenstrange_googleauth//jar"],
    )

  if "org_slf4j_slf4j_log4j12" not in excludes:
    native.java_library(
        name = "org_slf4j_slf4j_log4j12",
        visibility = ["//visibility:public"],
        exports = ["@org_slf4j_slf4j_log4j12//jar"],
        runtime_deps = [
            ":log4j_log4j",
        ],
    )

  if "log4j_log4j" not in excludes:
    native.java_library(
        name = "log4j_log4j",
        visibility = ["//visibility:public"],
        exports = ["@log4j_log4j//jar"],
    )

  if "javax_servlet_javax_servlet_api" not in excludes:
    native.java_library(
        name = "javax_servlet_javax_servlet_api",
        visibility = ["//visibility:public"],
        exports = ["@javax_servlet_javax_servlet_api//jar"],
    )

