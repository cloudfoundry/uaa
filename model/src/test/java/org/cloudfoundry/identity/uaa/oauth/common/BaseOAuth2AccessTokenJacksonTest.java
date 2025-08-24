package org.cloudfoundry.identity.uaa.oauth.common;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
abstract class BaseOAuth2AccessTokenJacksonTest {
    protected static final String ACCESS_TOKEN_EMPTYSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\"}";

    protected static final String ACCESS_TOKEN_BROKENEXPIRES = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":\"10\",\"scope\":\"\"}";

    protected static final String ACCESS_TOKEN_MULTISCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"read write\"}";

    protected static final String ACCESS_TOKEN_ARRAYSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":[\"read\",\"write\"]}";

    protected static final String ACCESS_TOKEN_NOSCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10}";

    protected static final String ACCESS_TOKEN_NOREFRESH = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"expires_in\":10}";

    protected static final String ACCESS_TOKEN_SINGLESCOPE = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"write\"}";

    protected static final String ACCESS_TOKEN_ADDITIONAL_INFO = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"one\":\"two\",\"three\":4,\"five\":{\"six\":7}}";

    protected static final String ACCESS_TOKEN_ZERO_EXPIRES = "{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"expires_in\":0}";

    @Mock
    protected Date expiration;

    protected DefaultOAuth2AccessToken accessToken;

    protected Map<String, Object> additionalInformation;

    public BaseOAuth2AccessTokenJacksonTest() {
        super();
    }

    @BeforeEach
    void setUp() {
        accessToken = new DefaultOAuth2AccessToken("token-value");
        accessToken.setExpiration(expiration);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh-value");
        accessToken.setRefreshToken(refreshToken);
        Set<String> scope = new TreeSet<>();
        scope.add("read");
        scope.add("write");
        accessToken.setScope(scope);
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("one", "two");
        map.put("three", 4);
        map.put("five", Collections.singletonMap("six", 7));
        additionalInformation = map;
    }
}