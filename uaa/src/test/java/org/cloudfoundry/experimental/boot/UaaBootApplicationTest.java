package org.cloudfoundry.experimental.boot;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code org.cloudfoundry.router.jakarta.ClientCertificateMapperAutoConfiguration} (from
 * {@code java-buildpack-client-certificate-mapper-jakarta}) is a {@code @ConditionalOnCloudPlatform
 * (CLOUD_FOUNDRY)} {@code @Configuration} class that registers its own
 * {@code ClientCertificateMapper} filter at {@code Ordered.HIGHEST_PRECEDENCE} -- ahead of
 * {@code RawPeerCertificateCaptureFilter} (order -300). If Spring Boot's auto-configuration
 * import mechanism ever proposed it as a candidate (it does not today: the jar carries no
 * {@code spring.factories} / {@code AutoConfiguration.imports} entry naming it, so nothing
 * currently triggers the import), that filter would overwrite the servlet
 * {@code X509Certificate} attribute with XFCC-derived data before the genuine TLS peer
 * certificate is captured, defeating direct-connection mTLS authentication. This test does not
 * boot a Spring context (a live check would additionally require simulating
 * {@code CloudPlatform.CLOUD_FOUNDRY} detection to be meaningful); it asserts the exclusion is
 * declared, which is what makes the outcome not depend on whether the jar ever starts
 * advertising the auto-configuration through the standard mechanism in some future version.
 *
 * <p>Asserted by name, not by class literal: the mapper jar is not on this module's compile
 * classpath (see {@link UaaBootApplication}'s javadoc), so the exclusion itself is by name too.
 */
class UaaBootApplicationTest {

    private static final String MAPPER_AUTO_CONFIGURATION =
            "org.cloudfoundry.router.jakarta.ClientCertificateMapperAutoConfiguration";

    @Test
    void excludesTheBuildpackCertificateMapperAutoConfiguration() {
        SpringBootApplication annotation = UaaBootApplication.class.getAnnotation(SpringBootApplication.class);

        assertThat(annotation).isNotNull();
        assertThat(annotation.excludeName())
                .as("ClientCertificateMapperAutoConfiguration registers a competing filter at "
                        + "Ordered.HIGHEST_PRECEDENCE, ahead of RawPeerCertificateCaptureFilter (-300); "
                        + "it must never be allowed to activate")
                .contains(MAPPER_AUTO_CONFIGURATION);
    }
}
