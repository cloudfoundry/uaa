package org.cloudfoundry.experimental.boot;

import org.cloudfoundry.identity.uaa.UaaApplicationConfiguration;
import org.cloudfoundry.identity.uaa.UaaStatsdConfiguration;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

/**
 * Excludes {@code org.cloudfoundry.router.jakarta.ClientCertificateMapperAutoConfiguration}, the
 * {@code java-buildpack-client-certificate-mapper-jakarta} library's own {@code @Configuration}
 * (activated by {@code @ConditionalOnCloudPlatform(CLOUD_FOUNDRY)}). That class registers a
 * second {@code ClientCertificateMapper} filter at {@code Ordered.HIGHEST_PRECEDENCE} -- ahead
 * of {@code RawPeerCertificateCaptureFilter} (order -300) -- which would overwrite the servlet
 * {@code X509Certificate} attribute with XFCC-derived data before the genuine TLS peer
 * certificate is captured, defeating direct-connection (non-proxy) mTLS authentication and the
 * capture filter's own guard against a proxy authenticating as the client it forwards for.
 * {@code SpringServletXmlFiltersConfiguration} registers the same filter class itself, reached
 * via reflection specifically to control its order (-200); this exclusion ensures that is the
 * only registration that can ever be active, regardless of whether this jar's packaging ever
 * starts advertising the auto-configuration through the standard Spring Boot import mechanism.
 *
 * <p>Excluded by name ({@code excludeName}), not by class literal, because the mapper jar is an
 * {@code implementation}-scoped dependency of the {@code server} module -- present on this
 * module's runtime classpath (transitively, so the reflection-based registration above works),
 * but deliberately not on its compile classpath.
 */
@SpringBootApplication(excludeName = "org.cloudfoundry.router.jakarta.ClientCertificateMapperAutoConfiguration")
@Import({UaaBootConfiguration.class, UaaApplicationConfiguration.class, UaaStatsdConfiguration.class})
public class UaaBootApplication {
    public static void main(String... args) {
        //make spring boot work with UAA beans
        System.setProperty("spring.main.allow-bean-definition-overriding", "true");
        System.setProperty("spring.main.allow-circular-references", "true");
        //System.setProperty("server.servlet.context-path", "/uaa");

        //debug spring filters
        //System.setProperty("logging.level.org.springframework.security", "TRACE");


        //BELOW ARE INTEGRATION TEST PROPERTIES - NOW SET IN build.gradle
        //String base = System.getProperty(
        //        "uaa.root.dir",
        //        System.getProperty("user.dir")
        //);

        //set up tomcat base directory
        //String tomcatBase = base + "/scripts/boot/tomcat/";
        //new File(tomcatBase+"/work").mkdirs();
        //new File(tomcatBase+"/webapps").mkdirs();
        //System.setProperty("server.tomcat.basedir", tomcatBase);

        //read the uaa.yml file out of the scripts/boot dir
        //String configPath = base + "/scripts/boot";
        //System.setProperty("CLOUDFOUNDRY_CONFIG_PATH", configPath);

        //configure sample properties for testing
        //System.setProperty("smtp.host", "localhost");
        //System.setProperty("smtp.port", "2525");
        //System.setProperty("java.security.egd", "file:/dev/./urandom");
        //System.setProperty("spring.profiles.active", "hsqldb");


        //start the application
        SpringApplication application = new SpringApplication(UaaBootApplication.class);
        application.addInitializers(new YamlServletProfileInitializer());
        application.run(args);
    }
}
