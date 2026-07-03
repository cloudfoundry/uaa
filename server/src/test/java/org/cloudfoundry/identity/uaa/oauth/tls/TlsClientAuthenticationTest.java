package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class TlsClientAuthenticationTest {

    private TlsClientAuthentication service;

    @BeforeEach
    void setUp() {
        service = new TlsClientAuthentication();
    }

    @Test
    void nullCertReturnsEmptyOptional() {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("...", null);
        assertThat(service.validateClientCert(null, config)).isEmpty();
    }

    @Test
    void nullConfigReturnsEmptyOptional() {
        X509Certificate cert = mock(X509Certificate.class);
        assertThat(service.validateClientCert(cert, null)).isEmpty();
    }

    @Test
    void invalidCaThrowsInvalidClientDetailsException() {
        X509Certificate cert = mock(X509Certificate.class);
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration("not-a-cert", null);
        assertThatThrownBy(() -> service.validateClientCert(cert, config))
                .hasMessageContaining("tls_client_auth");
    }
}
