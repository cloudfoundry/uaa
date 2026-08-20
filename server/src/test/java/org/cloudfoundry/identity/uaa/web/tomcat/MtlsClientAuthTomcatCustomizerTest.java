package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.catalina.connector.Connector;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;

import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

class MtlsClientAuthTomcatCustomizerTest {

    @Test
    void setsOptionalNoCaWhenMtlsEnabled() {
        MtlsClientAuthTomcatCustomizer customizer = new MtlsClientAuthTomcatCustomizer(true);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);

        customizer.customize(factory);

        Connector connector = new Connector();
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        connector.addSslHostConfig(sslHostConfig);
        factory.getConnectorCustomizers().forEach(c -> c.customize(connector));

        assertThat(sslHostConfig.getCertificateVerification())
                .isEqualTo(SSLHostConfig.CertificateVerification.OPTIONAL_NO_CA);
    }

    @Test
    void doesNothingWhenMtlsDisabled() {
        MtlsClientAuthTomcatCustomizer customizer = new MtlsClientAuthTomcatCustomizer(false);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);

        customizer.customize(factory);

        assertThat(factory.getConnectorCustomizers()).isEmpty();
    }

    @Test
    void registersTheFipsBouncyCastleJsseProviderIdempotently() {
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();

        assertThat(Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME)).isNotNull();
        BouncyCastleJsseProvider registered =
                (BouncyCastleJsseProvider) Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        assertThat(registered.isFipsMode()).isTrue();
    }
}
