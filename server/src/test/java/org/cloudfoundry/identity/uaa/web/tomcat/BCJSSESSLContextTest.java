package org.cloudfoundry.identity.uaa.web.tomcat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BCJSSESSLContextTest {

    @BeforeEach
    void setUp() {
        MtlsClientAuthTomcatCustomizer.ensureJsseProviderRegistered();
    }

    @Test
    void supportsTls12AndTls13FromTheFipsBouncyCastleJsseProvider() throws Exception {
        BCJSSESSLContext context = new BCJSSESSLContext("TLS");
        context.init(null, null, null);

        assertThat(context.getSupportedSSLParameters().getProtocols()).contains("TLSv1.3", "TLSv1.2");
    }
}
