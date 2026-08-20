package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
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
        assertThat(sslHostConfig.getTrustManagerClassName()).isEqualTo(NoAcceptedIssuersTrustManager.class.getName());
    }

    @Test
    void usesTheBouncyCastleJsseImplementationWhenMtlsEnabled() {
        MtlsClientAuthTomcatCustomizer customizer = new MtlsClientAuthTomcatCustomizer(true);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);
        customizer.customize(factory);

        Connector connector = new Connector();
        factory.getConnectorCustomizers().forEach(c -> c.customize(connector));

        assertThat(((AbstractHttp11Protocol<?>) connector.getProtocolHandler()).getSslImplementationName())
                .isEqualTo(BCJSSESslImplementation.class.getName());
    }

    @Test
    void doesNotExcludeTlsV13FromTheConnectorWhenMtlsEnabled() {
        MtlsClientAuthTomcatCustomizer customizer = new MtlsClientAuthTomcatCustomizer(true);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);
        customizer.customize(factory);

        Connector connector = new Connector();
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        connector.addSslHostConfig(sslHostConfig);
        factory.getConnectorCustomizers().forEach(c -> c.customize(connector));

        assertThat(sslHostConfig.getProtocols())
                .as("TLS 1.3 must not be excluded once the connector is served by BCJSSE")
                .doesNotContain("all,-TLSv1.3");
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
