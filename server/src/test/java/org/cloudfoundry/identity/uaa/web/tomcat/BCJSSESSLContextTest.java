package org.cloudfoundry.identity.uaa.web.tomcat;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BCJSSESSLContextTest {

    @BeforeEach
    void setUp() {
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();
    }

    @AfterEach
    void tearDown() {
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();
    }

    @Test
    void supportsTls12AndTls13FromTheFipsBouncyCastleJsseProvider() throws Exception {
        BCJSSESSLContext context = new BCJSSESSLContext("TLS");
        context.init(null, null, null);

        assertThat(context.getSupportedSSLParameters().getProtocols()).contains("TLSv1.3", "TLSv1.2");
    }

    @Test
    void throwsWhenTheBcjsseProviderIsNotRegistered() {
        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);

        assertThatThrownBy(() -> new BCJSSESSLContext("TLS"))
                .isInstanceOf(NoSuchAlgorithmException.class)
                .hasMessageContaining("ensureJsseProviderRegistered");
    }
}
