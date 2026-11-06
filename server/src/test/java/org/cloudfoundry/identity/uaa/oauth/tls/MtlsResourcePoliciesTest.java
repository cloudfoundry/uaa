package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.zone.MtlsResourcePolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MtlsResourcePoliciesTest {

    private static final String RESOURCE = "https://sts.example.com";

    @Test
    void resolvesOnlyTheNamedPolicyFromTheSuppliedZone() {
        Map<String, Object> client = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF, "federation");

        assertThat(MtlsResourcePolicies.resolve(
                client, Map.of("federation", policy(RESOURCE))))
                .containsExactly(RESOURCE);
        assertThatThrownBy(() -> MtlsResourcePolicies.resolve(
                client, Map.of("other-zone-policy", policy(RESOURCE))))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("unknown mTLS resource policy");
    }

    @Test
    void resolvesCurrentPolicyContentsWithoutChangingTheClientReference() {
        Map<String, Object> client = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF, "federation");
        Map<String, MtlsResourcePolicy> policies =
                new HashMap<>(Map.of("federation", policy(RESOURCE)));

        assertThat(MtlsResourcePolicies.resolve(client, policies)).containsExactly(RESOURCE);

        policies.put("federation", policy("api://AzureADTokenExchange"));

        assertThat(MtlsResourcePolicies.resolve(client, policies))
                .containsExactly("api://AzureADTokenExchange");
        assertThat(client).containsEntry(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF, "federation");
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-a-uri", "https://api.example.com#fragment", " "})
    void rejectsInvalidPolicyResources(String resource) {
        assertThatThrownBy(() -> MtlsResourcePolicies.validate(
                Map.of("federation", policy(resource))))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("federation");
    }

    @Test
    void rejectsEmptyPolicyAndInvalidName() {
        assertThatThrownBy(() -> MtlsResourcePolicies.validate(
                Map.of("federation", policy())))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("must not be empty");
        assertThatThrownBy(() -> MtlsResourcePolicies.validate(
                Map.of("invalid name", policy(RESOURCE))))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("name");
    }

    @Test
    void inlineListAndReferenceAreMutuallyExclusive() {
        assertThatThrownBy(() -> MtlsResourcePolicies.resolve(Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES, List.of(RESOURCE),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF, "federation"),
                Map.of("federation", policy(RESOURCE))))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("mutually exclusive");
    }

    private static MtlsResourcePolicy policy(String... resources) {
        MtlsResourcePolicy policy = new MtlsResourcePolicy();
        policy.setAllowedResources(List.of(resources));
        return policy;
    }
}
