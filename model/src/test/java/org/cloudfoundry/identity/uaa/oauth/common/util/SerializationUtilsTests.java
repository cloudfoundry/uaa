package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.Test;
import org.springframework.util.SerializationUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class SerializationUtilsTests {

    @Test
    public void deserializeAllowedClasses() {
        deserializeAllowedClasses(new DefaultOAuth2AccessToken("access-token-" + UUID.randomUUID()));

        deserializeAllowedClasses(new DefaultExpiringOAuth2RefreshToken(
                "access-token-" + UUID.randomUUID(), new Date()));

        deserializeAllowedClasses("xyz");
        deserializeAllowedClasses(new HashMap<String, String>());
    }

    private void deserializeAllowedClasses(Object object) {
        byte[] bytes = SerializationUtils.serialize(object);
        assertNotNull(bytes);
        assertTrue(bytes.length > 0);

        Object clone = SerializationUtils.deserialize(bytes);
        assertNotNull(clone);
        assertEquals(object, clone);
    }

    @Test
    public void deserializeCustomClasses() {
        OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        byte[] bytes = SerializationUtils.serialize(accessToken);
        OAuth2AccessToken clone = (OAuth2AccessToken) SerializationUtils.deserialize(bytes);
        assertNotNull(clone);
        assertEquals(accessToken, clone);
    }

    @Test
    public void deserializeNotAllowedCustomClasses() {
        OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        byte[] bytes = SerializationUtils.serialize(accessToken);
        OAuth2AccessToken clone = (OAuth2AccessToken) SerializationUtils.deserialize(bytes);
        assertNotNull(clone);
        assertEquals(accessToken, clone);
    }

    @Test
    public void paserQuery() {
        Map<String, String> queryMap = OAuth2Utils.extractMap("param=value&param2=value2&param3=");
        assertEquals(3, queryMap.size());
        assertEquals(0, OAuth2Utils.extractMap("").size());
    }
}