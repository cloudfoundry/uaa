package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TlsClientAuthConfigurationReaderTest {

    @Test
    void read_withoutWorkloadTrust_returnsNull() {
        assertThat(TlsClientAuthConfigurationReader.read(null)).isNull();
        assertThat(TlsClientAuthConfigurationReader.read(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, "CN=app"))).isNull();
    }

    @Test
    void read_flatConfiguration_populatesEverySetting() {
        Map<String, Object> info = new HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF, "diego");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-pem");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN, "CN=router");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "{app_id}");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI, "spiffe://cf/app");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, " ");

        TlsClientAuthConfiguration config = TlsClientAuthConfigurationReader.read(info);

        assertThat(config).isNotNull();
        assertThat(config.getTrustedCaPem()).isNull();
        assertThat(config.getTrustedCaRef()).isEqualTo("diego");
        assertThat(config.getTrustedProxyCaPem()).isEqualTo("proxy-pem");
        assertThat(config.getTrustedProxySubjectDn()).isEqualTo("CN=router");
        assertThat(config.getSubTemplate()).isEqualTo("{app_id}");
        assertThat(config.getSanUri()).isEqualTo("spiffe://cf/app");
        assertThat(config.getSubjectDn()).as("blank values count as absent").isNull();
    }

    @ParameterizedTest
    @MethodSource("jsonStringAndParsedForms")
    void read_jsonSettings_acceptStringAndParsedForms(Object mappings, Object audTemplates, Object requiredClaims,
            Object allowedResources) {
        TlsClientAuthConfiguration config = TlsClientAuthConfigurationReader.read(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem",
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, mappings,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, audTemplates,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, requiredClaims,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES, allowedResources));

        assertThat(config.getClaimMappings()).singleElement()
                .satisfies(mapping -> assertThat(mapping.getClaim()).isEqualTo("app_id"));
        assertThat(config.getAudTemplates()).containsExactly("{app_id}");
        assertThat(config.getRequiredClaims()).containsExactlyEntriesOf(Map.of("app_id", "a1"));
        assertThat(config.getAllowedResources()).containsExactly("https://api.example.com");
    }

    static Stream<Object[]> jsonStringAndParsedForms() {
        return Stream.of(
                new Object[]{"[{\"field\":\"subject_cn\",\"claim\":\"app_id\"}]", "[\"{app_id}\"]",
                        "{\"app_id\":\"a1\"}", "[\"https://api.example.com\"]"},
                new Object[]{List.of(Map.of("field", "subject_cn", "claim", "app_id")), List.of("{app_id}"),
                        Map.of("app_id", "a1"), List.of("https://api.example.com")});
    }

    @ParameterizedTest
    @MethodSource("unreadableSettings")
    void read_unreadableJsonSetting_throws(String key, Object value) {
        assertThatThrownBy(() -> TlsClientAuthConfigurationReader.read(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem", key, value)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    static Stream<Object[]> unreadableSettings() {
        return Stream.of(
                new Object[]{TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, "this is not json"},
                new Object[]{TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, Map.of("a", "b")},
                new Object[]{TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, List.of("x")},
                new Object[]{TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES, 42});
    }

    @Test
    void readAllowedResources_absent_returnsNull() {
        assertThat(TlsClientAuthConfigurationReader.readAllowedResources(Map.of())).isNull();
        assertThat(TlsClientAuthConfigurationReader.readAllowedResources(null)).isNull();
    }
}
