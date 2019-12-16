package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class TokenPolicyTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void json_has_expected_properties() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setAccessTokenValidity(1234);
        tokenPolicy.setRefreshTokenValidity(9876);
        tokenPolicy.setKeys(Collections.singletonMap("aKeyId", "KeyKeyKey"));

        String json = JsonUtils.writeValueAsString(tokenPolicy);
        Map properties = JsonUtils.readValue(json, Map.class);

        assertNotNull(properties);
        assertEquals(1234, properties.get("accessTokenValidity"));
        assertEquals(9876, properties.get("refreshTokenValidity"));
        assertNotNull(properties.get("keys"));
        Map keys = (Map) properties.get("keys");
        assertNotNull(keys);
        assertEquals(keys.size(), 1);
        assertEquals("KeyKeyKey", ((Map) keys.get("aKeyId")).get("signingKey"));
    }

    @Test
    public void test_default_values() {
        TokenPolicy policy = new TokenPolicy();
        assertFalse(policy.isRefreshTokenUnique());
        assertFalse(policy.isJwtRevocable());
        assertEquals(TokenConstants.TokenFormat.JWT.getStringValue(), policy.getRefreshTokenFormat());
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullSigningKey() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("key-id", null));
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptySigningKey() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("key-id", "             "));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullKeyId() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap(null, "signing-key"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyKeyId() {
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap(" ", "signing-key"));
    }

    @Test
    public void deserializationOfTokenPolicyWithVerificationKey_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"verificationKey\":\"some-verification-key-1\",\"signingKey\":\"some-signing-key-1\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertEquals(tokenPolicy.getKeys().get("key-id-1"), "some-signing-key-1");
    }

    @Test
    public void tokenPolicy_whenInvalidUniquenessValue_throwsException() {

        TokenPolicy tokenPolicy = new TokenPolicy();
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Invalid refresh token format invalid. Acceptable values are: [opaque, jwt]");

        tokenPolicy.setRefreshTokenFormat("invalid");
    }

    @Test
    public void deserializationOfTokenPolicyWithNoActiveKeyIdWithMultipleKeys_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"signingKey\":\"some-signing-key-1\"},\"key-id-2\":{\"signingKey\":\"some-signing-key-2\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertEquals(tokenPolicy.getKeys().get("key-id-1"), "some-signing-key-1");
        assertEquals(tokenPolicy.getKeys().get("key-id-2"), "some-signing-key-2");
    }
}
