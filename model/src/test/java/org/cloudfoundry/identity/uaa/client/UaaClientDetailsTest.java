package org.cloudfoundry.identity.uaa.client;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

class UaaClientDetailsTest {

    @Nested
    class TlsClientAuthEquality {
        private UaaClientDetails configuredClient(boolean useReference) {
            UaaClientDetails client = new UaaClientDetails("mtls-client", "resource", "scope",
                    "client_credentials", "uaa.resource");
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(useReference ? null : "ca-pem", null);
            if (useReference) {
                config.setTrustedCaRef("workload");
            }
            config.setSubjectDn("CN=workload");
            client.setTlsClientAuthConfiguration(config);
            return client;
        }

        private UaaClientDetails loadedClient(UaaClientDetails configured) {
            UaaClientDetails client = new UaaClientDetails("mtls-client", "resource", "scope",
                    "client_credentials", "uaa.resource");
            client.setAdditionalInformation(configured.getAdditionalInformation());
            assertThat(client.getTlsClientAuthConfiguration()).isNull();
            assertThat(client.getAdditionalInformation()).isEqualTo(configured.getAdditionalInformation());
            return client;
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void typedAndLoadedClientsWithIdenticalPersistedSettingsAreEqual(boolean useReference) {
            UaaClientDetails configured = configuredClient(useReference);
            UaaClientDetails loaded = loadedClient(configured);
            assertThat(configured).as("the transient mirror must not change persisted client equality").isEqualTo(loaded);
            assertThat(loaded).isEqualTo(configured);
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void typedAndLoadedClientsWithIdenticalPersistedSettingsHaveEqualHashCodes(boolean useReference) {
            UaaClientDetails configured = configuredClient(useReference);
            UaaClientDetails loaded = loadedClient(configured);
            assertThat(configured.hashCode()).as("hashing must use the same persisted identity as equality")
                    .isEqualTo(loaded.hashCode());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void loadedClientCanFindAnEquivalentTypedClientInAHashSet(boolean useReference) {
            UaaClientDetails configured = configuredClient(useReference);
            UaaClientDetails loaded = loadedClient(configured);
            assertThat(new HashSet<>(Set.of(configured))).as("client cache membership must survive loading from storage")
                    .contains(loaded);
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void differentPersistedTrustSettingsRemainUnequal(boolean useReference) {
            UaaClientDetails configured = configuredClient(useReference);
            UaaClientDetails loaded = loadedClient(configured);
            loaded.addAdditionalInformation(useReference ? TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF
                    : TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "different-trust");
            assertThat(configured).isNotEqualTo(loaded);
            assertThat(loaded).isNotEqualTo(configured);
        }
    }

    @Nested
    class Creation {
        private UaaClientDetails testClient;

        @BeforeEach
        void setUp() {
            testClient = new UaaClientDetails(
                    "test",
                    "",
                    "test.none",
                    "",
                    "test.admin"
            );
        }

        @Test
        void copiesUaaBaseClientDetails() {
            testClient.setClientSecret("secret");
            UaaClientDetails copy = new UaaClientDetails(testClient);
            assertThat(copy.getClientId()).isEqualTo("test");
            assertThat(copy.getClientSecret()).isEqualTo("secret");
            assertThat(copy.getScope()).containsExactly("test.none");
            assertThat(copy.getResourceIds()).isEmpty();

            List<String> authorities = copy.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            assertThat(authorities).containsExactly("test.admin");
        }

        @Test
        void copiesAdditionalInformation() {
            testClient.setAdditionalInformation(Collections.singletonMap("key", "value"));
            UaaClientDetails copy = new UaaClientDetails(testClient);
            assertThat(copy.getAdditionalInformation())
                    .hasSize(1)
                    .containsEntry("key", "value");
        }

        @Test
        void copiesFlatTlsClientAuthAdditionalInformationWhenTypedConfigurationIsNull() {
            Map<String, Object> tlsClientAuthAdditionalInformation = Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "trusted-ca",
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, "claim-mappings",
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "sub-template",
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, "aud-templates",
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "trusted-proxy-ca",
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, "required-claims");
            testClient.setAdditionalInformation(tlsClientAuthAdditionalInformation);

            UaaClientDetails copy = new UaaClientDetails(testClient);

            assertThat(copy.getAdditionalInformation()).containsExactlyInAnyOrderEntriesOf(tlsClientAuthAdditionalInformation);
        }

        @Test
        void clientJwtConfig() {
            UaaClientDetails copy = new UaaClientDetails(testClient);
            copy.setClientJwtConfig("test");
            assertThat(copy.getClientJwtConfig()).isEqualTo("test");
        }

        @Test
        void equals() {
            UaaClientDetails copy = new UaaClientDetails(testClient);
            UaaClientDetails copy2 = new UaaClientDetails(testClient);
            copy.setClientJwtConfig("test");
            assertThat(copy2).isNotEqualTo(copy);
            assertThat(new UaaClientDetails()).isNotEqualTo(copy);
            copy.setClientJwtConfig(null);
            assertThat(copy2).isEqualTo(copy);
            assertThat(copy).isEqualTo(copy);
            assertThat(new UaaClientDetails()).isNotEqualTo(copy);
        }

        @Test
        void testHashCode() {
            UaaClientDetails copy = new UaaClientDetails(testClient);
            UaaClientDetails copy2 = new UaaClientDetails(testClient.getClientId(), "",
                    "test.none", "", "test.admin", null);
            assertThat(copy2).hasSameHashCodeAs(copy);
            copy.setClientJwtConfig("test");
            assertThat(copy2.hashCode()).isNotEqualTo(copy.hashCode());
        }
    }

    @Nested
    class WhenSettingScope {
        @Test
        void splitsScopesWhichIncludeAComma() {
            UaaClientDetails client = new UaaClientDetails(new UaaClientDetails());
            client.setScope(Collections.singleton("foo,bar"));
            assertThat(client.getScope()).containsExactlyInAnyOrder("foo", "bar");
        }
    }

    @Nested
    class BaseClientDetails {
        @Test
        void baseClientDetailsDefaultConstructor() {
            UaaClientDetails details = new UaaClientDetails();
            assertThat(details.getResourceIds()).hasToString("[]");
            assertThat(details.getScope()).hasToString("[]");
            assertThat(details.getAuthorizedGrantTypes()).hasToString("[]");
            assertThat(details.getAuthorities()).hasToString("[]");
        }

        @Test
        void baseClientDetailsConvenienceConstructor() {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            assertThat(details.getResourceIds()).hasToString("[]");
            assertThat(new TreeSet<>(details.getScope())).hasToString("[bar, foo]");
            assertThat(details.getAuthorizedGrantTypes()).hasToString("[authorization_code]");
            assertThat(details.getAuthorities()).hasToString("[ROLE_USER]");
        }

        @Test
        void baseClientDetailsAutoApprove() {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("read,write"));
            assertThat(details.isAutoApprove("read")).isTrue();
        }

        @Test
        void baseClientDetailsImplicitAutoApprove() {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("true"));
            assertThat(details.isAutoApprove("read")).isTrue();
        }

        @Test
        void baseClientDetailsNoAutoApprove() {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("none"));
            assertThat(details.isAutoApprove("read")).isFalse();
        }

        @Test
        void baseClientDetailsNullAutoApprove() {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            assertThat(details.isAutoApprove("read")).isFalse();
        }

        @Test
        void jsonSerialize() throws Exception {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            details.setClientId("foo");
            details.setClientSecret("bar");
            String value = new JsonMapper().writeValueAsString(details);
            assertThat(value).contains("client_id")
                    .contains("client_secret")
                    .contains("authorized_grant_types")
                    .contains("[\"ROLE_USER\"]");
        }

        @Test
        void jsonSerializeAdditionalInformation() throws Exception {
            UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            details.setClientId("foo");
            details.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
            String value = new JsonMapper().writeValueAsString(details);
            assertThat(value).contains("\"foo\":\"bar\"");
        }

        @Test
        void jsonDeserialize() throws Exception {
            String value = "{\"foo\":\"bar\",\"client_id\":\"foo\",\"scope\":[\"bar\",\"foo\"],\"authorized_grant_types\":[\"authorization_code\"],\"authorities\":[\"ROLE_USER\"]}";
            UaaClientDetails details = new JsonMapper().readValue(value, UaaClientDetails.class);
            UaaClientDetails expected = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
            expected.setAdditionalInformation(Collections.singletonMap("foo", (Object) "bar"));
            assertThat(details).isEqualTo(expected);
        }

        @Test
        void jsonDeserializeWithArraysAsStrings() throws Exception {
            // Collection values can be deserialized from space or comma-separated lists
            String value = "{\"foo\":\"bar\",\"client_id\":\"foo\",\"scope\":\"bar  foo\",\"authorized_grant_types\":\"authorization_code\",\"authorities\":\"ROLE_USER,ROLE_ADMIN\"}";
            UaaClientDetails details = new JsonMapper().readValue(value, UaaClientDetails.class);
            UaaClientDetails expected = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER,ROLE_ADMIN");
            expected.setAdditionalInformation(Collections.singletonMap("foo", (Object) "bar"));
            assertThat(details).isEqualTo(expected);
        }

        @Test
        void equalityOfValidity() {
            UaaClientDetails details = new UaaClientDetails();
            details.setAccessTokenValiditySeconds(100);
            UaaClientDetails other = new UaaClientDetails();
            other.setAccessTokenValiditySeconds(100);
            assertThat(other).isEqualTo(details);
        }

        @Test
        void isScoped() {
            UaaClientDetails details = new UaaClientDetails();
            assertThat(details.isScoped()).isFalse();
        }

        @Test
        void isSecretRequired() {
            UaaClientDetails details = new UaaClientDetails();
            assertThat(details.isSecretRequired()).isFalse();
        }

        @Test
        void tlsClientAuthConfigRoundTripsViaJson() throws Exception {
            UaaClientDetails details = new UaaClientDetails();
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
                "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
                null
            );
            details.setTlsClientAuthConfiguration(config);

            String json = new JsonMapper().writeValueAsString(details);
            UaaClientDetails deserialized = new JsonMapper().readValue(json, UaaClientDetails.class);

            Object raw = deserialized.getAdditionalInformation()
                    .get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
            assertThat(raw).isEqualTo(config.getTrustedCaPem());
        }

        @Test
        void setTlsClientAuthConfiguration_whenCleared_removesAllPersistedSettings() {
            UaaClientDetails details = new UaaClientDetails();
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
                    "trusted-ca", List.of(new TlsClientAuthConfiguration.ClaimMapping("field", "pattern", "claim")));
            config.setSubTemplate("sub-template");
            config.setAudTemplates(List.of("aud-template"));
            config.setTrustedProxyCaPem("trusted-proxy-ca");
            config.setRequiredClaims(Map.of("required-claim", "value"));

            details.setTlsClientAuthConfiguration(config);
            details.setTlsClientAuthConfiguration(null);

            assertThat(details.getAdditionalInformation()).doesNotContainKeys(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS);
        }

        @Test
        void setTlsClientAuthConfiguration_whenCleared_removesBoundAccessTokensPolicy() {
            UaaClientDetails details = new UaaClientDetails();
            details.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration("trusted-ca", null));
            details.addAdditionalInformation(TlsClientAuthConfiguration.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS, true);

            details.setTlsClientAuthConfiguration(null);

            assertThat(details.getAdditionalInformation())
                    .as("a binding policy without TLS trust would leave the client unable to get any token")
                    .doesNotContainKey(TlsClientAuthConfiguration.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS);
        }

        @Test
        void autoApprove() {
            UaaClientDetails details = new UaaClientDetails();
            assertThat(details.getAutoApproveScopes()).isNull();
        }

        @Test
        void testHashCode() {
            UaaClientDetails uaaClientDetails = new UaaClientDetails("admin", "uaa", "uaa.none",
                    "client_credentials", "none", null);
            uaaClientDetails.setRegisteredRedirectUri(Set.of("http://localhost:8080/uaa"));
            uaaClientDetails.setRefreshTokenValiditySeconds(1);
            uaaClientDetails.setAccessTokenValiditySeconds(1);
            assertThat(uaaClientDetails.hashCode()).isNotZero();
        }
    }

    @Nested
    class Equals {
        private UaaClientDetails testClient;
        private UaaClientDetails testClientCompare;

        @BeforeEach
        void setUp() {
            testClient = new UaaClientDetails("test", null, null, null, null);
            testClientCompare = new UaaClientDetails(testClient);
        }

        @Test
        void equals() {
            UaaClientDetails uaaClientDetails = new UaaClientDetails("admin", null, null,
                    null, null, null);
            UaaClientDetails uaaClientDetails1 = new UaaClientDetails(uaaClientDetails);
            assertThat(uaaClientDetails1).isEqualTo(uaaClientDetails);
            assertThat(new Object()).isNotEqualTo(uaaClientDetails);
            assertThat(uaaClientDetails).isNotNull();
        }

        @Test
        void equalScope() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setScope(Set.of("new"));
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalAdditionalInformation() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setAdditionalInformation(Map.of("n", "v"));
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalResourceIds() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setResourceIds(Set.of("resource"));
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalRegisteredRedirectUris() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setRegisteredRedirectUri(Set.of("http://localhost:8080/uaa"));
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalSecret() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setClientSecret("secret");
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalClientId() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setClientId("user");
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalAuthorizedGrantTypes() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setAuthorizedGrantTypes(Set.of("client_credentials"));
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalAuthorities() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setAuthorities(AuthorityUtils.createAuthorityList("none"));
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalRefreshTokenValiditySeconds() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setRefreshTokenValiditySeconds(1);
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }

        @Test
        void equalAccessTokenValiditySeconds() {
            assertThat(testClientCompare).isEqualTo(testClient);
            testClientCompare.setAccessTokenValiditySeconds(1);
            assertThat(testClientCompare).isNotEqualTo(testClient);
        }
    }

    @Nested
    class TlsClientAuthConfigurationMirroring {
        private static final String CA = "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n";

        @Test
        void namedTrustReferencesSurviveTypedConfigurationAndClearing() {
            TlsClientAuthConfiguration config = org.cloudfoundry.identity.uaa.util.JsonUtils.convertValue(Map.of(
                    "tls-client-auth-ca-ref", "workload", "tls-client-auth-trusted-proxy-ca-ref", "proxy"),
                    TlsClientAuthConfiguration.class);
            UaaClientDetails client = new UaaClientDetails();
            client.setTlsClientAuthConfiguration(config);
            assertThat(client.getAdditionalInformation())
                    .containsEntry("tls-client-auth-ca-ref", "workload")
                    .containsEntry("tls-client-auth-trusted-proxy-ca-ref", "proxy")
                    .doesNotContainKey(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
            client.setTlsClientAuthConfiguration(null);
            assertThat(client.getAdditionalInformation())
                    .doesNotContainKeys("tls-client-auth-ca-ref", "tls-client-auth-trusted-proxy-ca-ref");
        }

        private TlsClientAuthConfiguration fullConfiguration() {
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(CA, null);
            config.setAllowedResources(List.of("https://api.example.com"));
            config.setSubjectDn("CN=app");
            config.setSanDns("app.example.com");
            config.setSanUri("spiffe://acme/app");
            config.setSanIp("10.0.0.7");
            config.setSanEmail("svc@example.com");
            return config;
        }

        @Test
        void everyTypedFieldIsMirroredIntoAdditionalInformation() {
            UaaClientDetails client = new UaaClientDetails();
            client.setTlsClientAuthConfiguration(fullConfiguration());

            assertThat(client.getAdditionalInformation())
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, CA)
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES,
                            List.of("https://api.example.com"))
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, "CN=app")
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "app.example.com")
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI, "spiffe://acme/app")
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP, "10.0.0.7")
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL, "svc@example.com");
        }

        @Test
        void replacingTheConfigurationRemovesFieldsTheNewOneDoesNotSet() {
            UaaClientDetails client = new UaaClientDetails();
            client.setTlsClientAuthConfiguration(fullConfiguration());

            TlsClientAuthConfiguration replacement = new TlsClientAuthConfiguration(CA, null);
            replacement.setSubjectDn("CN=other");
            client.setTlsClientAuthConfiguration(replacement);

            assertThat(client.getAdditionalInformation())
                    .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, "CN=other")
                    .doesNotContainKeys(
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES,
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS,
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI,
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP,
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL);
        }

        @Test
        void clearingTheConfigurationRemovesEveryField() {
            UaaClientDetails client = new UaaClientDetails();
            client.setTlsClientAuthConfiguration(fullConfiguration());

            client.setTlsClientAuthConfiguration(null);

            assertThat(client.getAdditionalInformation()).doesNotContainKeys(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP,
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL);
        }
    }

    @Nested
    class Serialization {
        @Test
        void aClientWithATlsClientAuthConfigurationIsJavaSerializable() throws Exception {
            // ClientDetails is Serializable; the typed TlsClientAuthConfiguration is a derived view of the flat
            // additionalInformation (which is transient too) and must not make the object unserializable.
            UaaClientDetails client = new UaaClientDetails("mtls", "", "uaa.none", "client_credentials", "uaa.resource");
            client.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
                    "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n", null));

            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            try (java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(bytes)) {
                out.writeObject(client);
            }
            try (java.io.ObjectInputStream in = new java.io.ObjectInputStream(
                    new java.io.ByteArrayInputStream(bytes.toByteArray()))) {
                UaaClientDetails restored = (UaaClientDetails) in.readObject();
                assertThat(restored.getClientId()).isEqualTo("mtls");
            }
        }
    }
}
