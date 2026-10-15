package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlsClientAuthConfigurationReaderTest {

    private static final String CA = "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n";
    private static final String PROXY_CA = "-----BEGIN CERTIFICATE-----\nMIIBproxy\n-----END CERTIFICATE-----\n";

    @Test
    void readsEveryFlatKeyAsStoredByJdbc() {
        Map<String, Object> info = new HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, CA);
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, PROXY_CA);
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN, "CN=gorouter");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                "[{\"field\":\"subject_cn\",\"claim\":\"workload\"}]");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "{workload}");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, "[\"aud-{workload}\"]");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, "{\"workload\":\"w1\"}");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES, "[\"https://api.example.com\"]");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "w1.example.com");

        TlsClientAuthConfiguration config = TlsClientAuthConfigurationReader.read(info);

        assertThat(config.getTrustedCaPem()).isEqualTo(CA);
        assertThat(config.getTrustedProxyCaPem()).isEqualTo(PROXY_CA);
        assertThat(config.getTrustedProxySubjectDn()).isEqualTo("CN=gorouter");
        assertThat(config.getClaimMappings()).singleElement()
                .extracting(TlsClientAuthConfiguration.ClaimMapping::getClaim).isEqualTo("workload");
        assertThat(config.getSubTemplate()).isEqualTo("{workload}");
        assertThat(config.getAudTemplates()).containsExactly("aud-{workload}");
        assertThat(config.getRequiredClaims()).containsExactly(Map.entry("workload", "w1"));
        assertThat(config.getAllowedResources()).containsExactly("https://api.example.com");
        assertThat(config.getSanDns()).isEqualTo("w1.example.com");
    }

    @Test
    void readsAlreadyParsedListsAndMaps() {
        TlsClientAuthConfiguration config = TlsClientAuthConfigurationReader.read(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF, "instance-identity",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES, List.of("https://api.example.com"),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, Map.of("workload", "w1")));

        assertThat(config.getTrustedCaRef()).isEqualTo("instance-identity");
        assertThat(config.getAllowedResources()).containsExactly("https://api.example.com");
        assertThat(config.getRequiredClaims()).containsExactly(Map.entry("workload", "w1"));
    }

    @Test
    void clientWithoutMtlsKeysIsNotConfigured() {
        assertThat(TlsClientAuthConfigurationReader.read(null)).isNull();
        assertThat(TlsClientAuthConfigurationReader.read(Map.of("name", "ordinary"))).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA,
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF,
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN})
    void proxyTrustWithoutWorkloadTrustIsRejected(String proxyKey) {
        assertThatThrownBy(() -> TlsClientAuthConfigurationReader.read(Map.of(proxyKey, "value")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("proxy trust requires");
    }

    @Test
    void blankInlineCaIsRejected() {
        assertThatThrownBy(() -> TlsClientAuthConfigurationReader.read(
                Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, " ")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be read");
    }

    @Test
    void blankReferenceIsRejected() {
        assertThatThrownBy(() -> TlsClientAuthConfigurationReader.read(
                Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF, "")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must name a nonblank trust bundle");
    }

    @Test
    void unreadableJsonIsRejected() {
        assertThatThrownBy(() -> TlsClientAuthConfigurationReader.read(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, CA,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, "{not json")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("tls-client-auth configuration cannot be read");
    }
}
