package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class TokenPolicyTest {

    @Test
    void json_has_expected_properties() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setAccessTokenValidity(1234);
        tokenPolicy.setRefreshTokenValidity(9876);
        tokenPolicy.setKeys(Collections.singletonMap("aKeyId", "KeyKeyKey"));

        String json = JsonUtils.writeValueAsString(tokenPolicy);
        Map properties = JsonUtils.readValue(json, Map.class);

        assertThat(properties).isNotNull()
                .containsEntry("accessTokenValidity", 1234)
                .containsEntry("refreshTokenValidity", 9876)
                .containsKey("keys");
        Map keys = (Map) properties.get("keys");
        assertThat(keys).isNotNull()
                .hasSize(1);
        assertThat(((Map) keys.get("aKeyId"))).containsEntry("signingKey", "KeyKeyKey");
    }

    @Test
    void default_values() {
        TokenPolicy policy = new TokenPolicy();
        assertThat(policy.isRefreshTokenUnique()).isFalse();
        assertThat(policy.isJwtRevocable()).isFalse();
        assertThat(policy.isRefreshTokenRotate()).isFalse();
        assertThat(policy.getRefreshTokenFormat()).isEqualTo(TokenConstants.TokenFormat.OPAQUE.getStringValue());
    }

    @Test
    void set_values() {
        TokenPolicy policy = new TokenPolicy();
        policy.setRefreshTokenUnique(true);
        policy.setJwtRevocable(true);
        policy.setRefreshTokenRotate(true);
        policy.setRefreshTokenFormat(TokenConstants.TokenFormat.JWT.getStringValue());
        assertThat(policy.isRefreshTokenUnique()).isTrue();
        assertThat(policy.isJwtRevocable()).isTrue();
        assertThat(policy.isRefreshTokenRotate()).isTrue();
        assertThat(policy.getRefreshTokenFormat()).isEqualTo(TokenConstants.TokenFormat.JWT.getStringValue());
    }

    @Test
    void nullSigningKey() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                tokenPolicy.setKeys(Collections.singletonMap("key-id", null)));
    }

    @Test
    void emptySigningKey() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                tokenPolicy.setKeys(Collections.singletonMap("key-id", "             ")));
    }

    @Test
    void nullKeyId() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                tokenPolicy.setKeys(Collections.singletonMap(null, "signing-key")));
    }

    @Test
    void emptyKeyId() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                tokenPolicy.setKeys(Collections.singletonMap(" ", "signing-key")));
    }

    @Test
    void deserializationOfTokenPolicyWithVerificationKey_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"verificationKey\":\"some-verification-key-1\",\"signingKey\":\"some-signing-key-1\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningKey()).isEqualTo("some-signing-key-1");
    }

    @Test
    void tokenPolicy_whenInvalidUniquenessValue_throwsException() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        assertThatThrownBy(() -> tokenPolicy.setRefreshTokenFormat("invalid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid refresh token format invalid. Acceptable values are: [opaque, jwt]");
    }

    @Test
    void deserializationOfTokenPolicyWithNoActiveKeyIdWithMultipleKeys_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"signingKey\":\"some-signing-key-1\"},\"key-id-2\":{\"signingKey\":\"some-signing-key-2\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningKey()).isEqualTo("some-signing-key-1");
        assertThat(tokenPolicy.getKeys().get("key-id-2").getSigningKey()).isEqualTo("some-signing-key-2");
    }

    @Test
    void tokenPolicy_not_changed_if_keys_null() {
        final String sampleIdentityZone = getResourceAsString(getClass(), "SampleIdentityZone.json");
        IdentityZone identityZone = JsonUtils.readValue(sampleIdentityZone, IdentityZone.class);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningKey()).isEqualTo("some-signing-key-1");
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningCert()).isEqualTo("some-cert");
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningAlg()).isEqualTo("RS256");
        tokenPolicy.setKeys(null);
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningKey()).isEqualTo("some-signing-key-1");
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningCert()).isEqualTo("some-cert");
        assertThat(tokenPolicy.getKeys().get("key-id-1").getSigningAlg()).isEqualTo("RS256");
    }
}
