package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TokenPolicyTest {

    @Test
    public void json_has_expected_properties() throws Exception {
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
        assertEquals("KeyKeyKey", keys.get("aKeyId"));
    }


}