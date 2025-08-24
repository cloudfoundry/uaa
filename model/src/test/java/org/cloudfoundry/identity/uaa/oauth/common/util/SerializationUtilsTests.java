package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.Test;
import org.springframework.util.SerializationUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class SerializationUtilsTests {

    @Test
    void deserializeAllowedClasses() {
        deserializeAllowedClasses(new DefaultOAuth2AccessToken("access-token-" + UUID.randomUUID()));

        deserializeAllowedClasses(new DefaultExpiringOAuth2RefreshToken(
                "access-token-" + UUID.randomUUID(), new Date()));

        deserializeAllowedClasses("xyz");
        deserializeAllowedClasses(new HashMap<String, String>());
    }

    private void deserializeAllowedClasses(Object object) {
        byte[] bytes = SerializationUtils.serialize(object);
        assertThat(bytes).isNotEmpty();

        Object clone = SerializationUtils.deserialize(bytes);
        assertThat(clone).isEqualTo(object);
    }

    @Test
    void deserializeCustomClasses() {
        OAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        byte[] bytes = SerializationUtils.serialize(accessToken);
        OAuth2AccessToken clone = (OAuth2AccessToken) SerializationUtils.deserialize(bytes);
        assertThat(clone).isEqualTo(accessToken);
    }

    @Test
    void paserQuery() {
        Map<String, String> queryMap = OAuth2Utils.extractMap("param=value&param2=value2&param3=");
        assertThat(queryMap).hasSize(3);
        assertThat(OAuth2Utils.extractMap("")).isEmpty();
    }
}
