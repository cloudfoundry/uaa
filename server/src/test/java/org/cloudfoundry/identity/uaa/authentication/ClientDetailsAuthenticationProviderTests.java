package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

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

    @Test
    void tlsConfigIsDeserializedFromRawMapInAdditionalInfo() {
        // Simulate what happens when additionalInformation comes from the DB:
        // the JSON is parsed to a LinkedHashMap, not TlsClientAuthConfiguration
        Map<String, Object> rawMap = Map.of(
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n"
        );
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, rawMap);

        UaaClient mockClient = mock(UaaClient.class);
        when(mockClient.getAdditionalInformation()).thenReturn(additionalInfo);

        TlsClientAuthConfiguration config =
            ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration(mockClient);
        assertThat(config).isNotNull();
        assertThat(config.getTrustedCaPem())
            .isEqualTo("-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n");
    }
}
