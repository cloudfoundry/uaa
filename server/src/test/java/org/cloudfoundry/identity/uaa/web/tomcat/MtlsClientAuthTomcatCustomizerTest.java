package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;

import java.security.Provider;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    void failsFastWhenTheConnectorIsNotHttp11Based() {
        MtlsClientAuthTomcatCustomizer customizer = new MtlsClientAuthTomcatCustomizer(true);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(0);
        customizer.customize(factory);

        Connector connector = new Connector("AJP/1.3");

        assertThatThrownBy(() -> factory.getConnectorCustomizers().forEach(c -> c.customize(connector)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("HTTP/1.1");
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

    @Test
    void failsFastWhenAnExistingNonFipsProviderIsAlreadyRegisteredUnderTheBcjsseName() {
        // Simulates a non-FIPS provider having already claimed the "BCJSSE" provider name (e.g.
        // via JVM-wide java.security configuration) before this method runs -- must not be
        // silently trusted as the genuine FIPS BouncyCastleJsseProvider.
        //
        // Security.addProvider(Provider) is a no-op (returns -1) if a provider with the same
        // name is already registered -- and since Security providers are global, JVM-wide state
        // with no automatic teardown, another test in this class (or a prior run of this same
        // customizer) may have already registered the genuine FIPS provider under this name.
        // Remove any existing registration first so the impostor is guaranteed to actually take
        // its place, regardless of test execution order.
        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        Provider impostor = new Provider(BouncyCastleJsseProvider.PROVIDER_NAME, "1.0", "not actually BCJSSE") {
        };
        Security.addProvider(impostor);
        try {
            assertThatThrownBy(MtlsClientAuthTomcatCustomizer::ensureJsseProviderRegistered)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining(BouncyCastleJsseProvider.PROVIDER_NAME)
                    .hasMessageContaining(impostor.getClass().getName());
        } finally {
            Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        }
    }

    @Test
    void failsFastWhenTheGenuineProviderIsRegisteredButNotInFipsMode() {
        // Simulates the correct BouncyCastleJsseProvider class having already been registered under
        // the "BCJSSE" name, but constructed in non-FIPS mode -- a distinct failure mode from an
        // entirely different provider class claiming the name (see the "impostor" test above). The
        // error message must be specific to this case, not the generic "different provider" message.
        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        BouncyCastleJsseProvider nonFipsProvider = new BouncyCastleJsseProvider(false);
        Security.addProvider(nonFipsProvider);
        try {
            assertThatThrownBy(MtlsClientAuthTomcatCustomizer::ensureJsseProviderRegistered)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining(BouncyCastleJsseProvider.PROVIDER_NAME)
                    .hasMessageContaining("not")
                    .hasMessageContaining("FIPS mode")
                    .hasMessageNotContaining("a different provider is already registered");
        } finally {
            Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        }
    }

    @Test
    void succeedsWhenTheGenuineFipsProviderIsAlreadyRegisteredUnderTheBcjsseName() {
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();

        // Calling it again with the genuine FIPS provider already registered must not throw.
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();

        assertThat(Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME)).isNotNull();
    }
}
