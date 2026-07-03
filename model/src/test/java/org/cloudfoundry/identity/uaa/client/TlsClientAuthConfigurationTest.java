package org.cloudfoundry.identity.uaa.client;

import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TlsClientAuthConfigurationTest {

    private static final String EXAMPLE_CA = "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n";

    @Test
    void roundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"))
        );

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getTrustedCaPem()).isEqualTo(EXAMPLE_CA);
        assertThat(deserialized.getClaimMappings()).hasSize(1);
        assertThat(deserialized.getClaimMappings().get(0).getClaim()).isEqualTo("app_guid");
    }

    @Test
    void nullCaMeansNotConfigured() {
        assertThat(TlsClientAuthConfiguration.isConfigured(null)).isFalse();
        assertThat(TlsClientAuthConfiguration.isConfigured(new TlsClientAuthConfiguration(null, null))).isFalse();
    }

    @Test
    void nonNullCaMeansConfigured() {
        assertThat(TlsClientAuthConfiguration.isConfigured(
            new TlsClientAuthConfiguration(EXAMPLE_CA, null))).isTrue();
    }

    @Test
    void claimMappingWithoutPatternUsesFieldDirectly() {
        TlsClientAuthConfiguration.ClaimMapping mapping =
            new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "instance_guid");
        assertThat(mapping.getPattern()).isNull();
        assertThat(mapping.getClaim()).isEqualTo("instance_guid");
    }

    @Test
    void equalConfigurations() {
        TlsClientAuthConfiguration a = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"))
        );
        TlsClientAuthConfiguration b = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"))
        );
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void unequalWhenCaDiffers() {
        TlsClientAuthConfiguration a = new TlsClientAuthConfiguration("ca-a", null);
        TlsClientAuthConfiguration b = new TlsClientAuthConfiguration("ca-b", null);
        assertThat(a).isNotEqualTo(b);
    }
}
