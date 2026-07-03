package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientDetailsAuthenticationProviderTests {

    @Test
    void tlsClientAuthPathIsDetectedAsTlsClientAuth() {
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getRequestPath()).thenReturn("/oauth/mtls/token");
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isTrue();
    }

    @Test
    void regularTokenPathIsNotTlsClientAuth() {
        UaaAuthenticationDetails details = mock(UaaAuthenticationDetails.class);
        when(details.getRequestPath()).thenReturn("/oauth/token");
        assertThat(ClientDetailsAuthenticationProvider.isTlsClientAuthPath(details)).isFalse();
    }
}
