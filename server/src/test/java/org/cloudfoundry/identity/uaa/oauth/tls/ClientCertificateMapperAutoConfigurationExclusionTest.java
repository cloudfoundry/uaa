package org.cloudfoundry.identity.uaa.oauth.tls;

import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code org.cloudfoundry.router.jakarta.ClientCertificateMapperAutoConfiguration} (from
 * {@code java-buildpack-client-certificate-mapper-jakarta}) is a {@code @ConditionalOnCloudPlatform
 * (CLOUD_FOUNDRY)} {@code @Configuration} class that registers its own {@code ClientCertificateMapper}
 * filter at {@code Ordered.HIGHEST_PRECEDENCE} -- ahead of {@code RawPeerCertificateCaptureFilter}
 * (order -300). If it were ever activated, that filter would overwrite the servlet
 * {@code X509Certificate} attribute with XFCC-derived data before the genuine TLS peer certificate
 * is captured, defeating direct-connection (non-proxy) mTLS authentication and the capture filter's
 * own guard against a proxy authenticating as the client it forwards for.
 * {@code SpringServletXmlFiltersConfiguration} registers the same filter class itself, reached via
 * reflection specifically to control its order (-200); that must remain the only registration.
 *
 * <p>It is not activated today because the jar carries neither a {@code spring.factories} /
 * {@code AutoConfiguration.imports} entry naming it (so Spring Boot's {@code @EnableAutoConfiguration}
 * never imports it) nor a {@code META-INF/services/jakarta.servlet.ServletContainerInitializer}
 * entry naming {@code ClientCertificateMapperServletContainerInitializer} (so no standards-compliant
 * servlet container discovers it via SPI either). {@code @SpringBootApplication(exclude = ...)} was
 * tried as a permanent guard against a future dependency bump silently adding one of those, but
 * Spring Boot's exclusion validation throws {@code IllegalStateException} at application startup for
 * excluding a class that is not currently a registered auto-configuration candidate -- confirmed by
 * an actual boot failure when this was tried against the real bootWar, so it is not usable as a
 * defensive measure against a registration that does not exist yet.
 *
 * <p>This test is the substitute: it inspects the real merged runtime classpath (every jar's
 * contribution to these two SPI/auto-configuration marker files) and fails immediately, at test
 * time, the moment a dependency bump ever adds either registration -- before that reaches any real
 * deployment.
 */
class ClientCertificateMapperAutoConfigurationExclusionTest {

    private static final String MAPPER_AUTO_CONFIGURATION =
            "org.cloudfoundry.router.jakarta.ClientCertificateMapperAutoConfiguration";
    private static final String MAPPER_SERVLET_CONTAINER_INITIALIZER =
            "org.cloudfoundry.router.jakarta.ClientCertificateMapperServletContainerInitializer";

    @Test
    void mapperJarDoesNotRegisterItsOwnAutoConfiguration() throws IOException {
        assertThat(resourceLines("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"))
                .as("if this ever appears, ClientCertificateMapperAutoConfiguration would be imported "
                        + "automatically and register a filter at Ordered.HIGHEST_PRECEDENCE, ahead of "
                        + "RawPeerCertificateCaptureFilter (-300) -- see this test's class javadoc")
                .doesNotContain(MAPPER_AUTO_CONFIGURATION);
        assertThat(resourceLines("META-INF/spring.factories"))
                .as("the legacy Spring Boot auto-configuration registration mechanism")
                .noneMatch(line -> line.contains(MAPPER_AUTO_CONFIGURATION));
    }

    @Test
    void mapperJarDoesNotRegisterAServletContainerInitializer() throws IOException {
        assertThat(resourceLines("META-INF/services/jakarta.servlet.ServletContainerInitializer"))
                .as("if this ever appears, a standards-compliant servlet container (e.g. the CF Java "
                        + "buildpack's Tomcat) would invoke ClientCertificateMapperServletContainerInitializer "
                        + "via SPI, registering an unordered, unguarded filter for every request path")
                .doesNotContain(MAPPER_SERVLET_CONTAINER_INITIALIZER);
    }

    /** Every line, from every jar on the classpath, that contributes to {@code resourcePath}. */
    private List<String> resourceLines(String resourcePath) throws IOException {
        List<String> lines = new ArrayList<>();
        Enumeration<URL> resources = getClass().getClassLoader().getResources(resourcePath);
        while (resources.hasMoreElements()) {
            URL url = resources.nextElement();
            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line.trim());
                }
            }
        }
        return lines;
    }
}
