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

    @Test
    void subTemplateRoundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
            EXAMPLE_CA,
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"))
        );
        config.setSubTemplate("o/{cf.org}/s/{cf.space}/a/{cf.app}");

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getSubTemplate()).isEqualTo("o/{cf.org}/s/{cf.space}/a/{cf.app}");
    }

    @Test
    void audTemplatesRoundTripsViaJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        config.setAudTemplates(List.of(
            "o/{cf.org}/s/{cf.space}/a/{cf.app}",
            "o/{cf.org}/s/{cf.space}",
            "o/{cf.org}"
        ));

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);
        TlsClientAuthConfiguration deserialized = mapper.readValue(json, TlsClientAuthConfiguration.class);

        assertThat(deserialized.getAudTemplates()).containsExactly(
            "o/{cf.org}/s/{cf.space}/a/{cf.app}",
            "o/{cf.org}/s/{cf.space}",
            "o/{cf.org}"
        );
    }

    @Test
    void nullSubTemplateAndAudTemplatesOmittedFromJson() throws Exception {
        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        // subTemplate and audTemplates left null

        JsonMapper mapper = new JsonMapper();
        String json = mapper.writeValueAsString(config);

        assertThat(json).doesNotContain("tls-client-auth-sub-template");
        assertThat(json).doesNotContain("tls-client-auth-aud-templates");
    }

    @Test
    void equalityIncludesSubTemplateAndAudTemplates() {
        TlsClientAuthConfiguration a = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        a.setSubTemplate("o/{cf.org}");
        a.setAudTemplates(List.of("o/{cf.org}"));

        TlsClientAuthConfiguration b = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        b.setSubTemplate("o/{cf.org}");
        b.setAudTemplates(List.of("o/{cf.org}"));

        TlsClientAuthConfiguration c = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        c.setSubTemplate("different");

        TlsClientAuthConfiguration d = new TlsClientAuthConfiguration(EXAMPLE_CA, null);
        d.setSubTemplate("o/{cf.org}");   // same as a
        // d.audTemplates left null        // differs from a

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
        assertThat(a).isNotEqualTo(c);
        assertThat(a).isNotEqualTo(d);
    }
}
