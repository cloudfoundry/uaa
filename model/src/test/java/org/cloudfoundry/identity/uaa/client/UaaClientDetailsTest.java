package org.cloudfoundry.identity.uaa.client;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

class UaaClientDetailsTest {

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
}
