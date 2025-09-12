package org.cloudfoundry.identity.uaa.degraded;


import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.provider.token.MockClientAssertionHeader;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantDegradedIntegrationTest {

    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final String ASSERTION = "assertion";
    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private final static String DEVICE_ID = "d10";
    private final static String DEVICE_CLIENT_ID = "c1";

    protected final static Logger logger = LoggerFactory.getLogger(JwtBearerGrantDegradedIntegrationTest.class);

    @Value("${PUBLISHED_HOST:localhost:8080/uaa}")
    String publishedHost;

    @Value("${CF_DOMAIN:run.aws-usw02-dev.ice.predix.io}")
    String cfDomain;

    @Value("${PUBLISHED_DOMAIN:#{null}}")
    String publishedDomain;

    @Value("${PROTOCOL:#{null}}")
    String protocol;

    @Value("${BASIC_AUTH_CLIENT_ID:app}")
    String basicAuthClientId;

    @Value("${BASIC_AUTH_CLIENT_SECRET:appclientsecret}")
    String basicAuthClientSecret;

    @Value("${RUN_AGAINST_CLOUD:false}")
    String runAgainstCloud;

    private String baseUaaZoneUrl;

    private String audience;

    private final RestTemplate tokenRestTemplate = new RestTemplate();

    private HttpHeaders getHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        String assertionHeader = new MockClientAssertionHeader().mockSignedHeader(System.currentTimeMillis() / 1000,
                DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);
        return headers;
    }

    @Before
    public void setup() {
        if (StringUtils.hasText(protocol)) {
            protocol = protocol.contains("://") ? protocol : protocol + "://";
        } else {
            protocol = Boolean.valueOf(runAgainstCloud) ? "https://" : "http://";
        }
        if (StringUtils.hasText(publishedDomain)) {
            baseUaaZoneUrl = protocol + "test-jwt-zone." + publishedDomain;
        } else {
            baseUaaZoneUrl = Boolean.valueOf(runAgainstCloud) ? (protocol + "test-jwt-zone." + publishedHost + "." + cfDomain) : (protocol + "test-jwt-zone." + publishedHost);
        }
        audience = baseUaaZoneUrl + "/oauth/token";
    }

    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        doJwtBearerGrantRequest(getHttpHeaders());
    }

    private void doJwtBearerGrantRequest(final HttpHeaders headers) throws Exception {
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, audience);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(this.baseUaaZoneUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        // verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        assertAccessToken(accessToken);

        MultiValueMap<String, String> tokenFormData = new LinkedMultiValueMap<>();
        tokenFormData.add("token", accessToken.getValue());

        headers.set("Authorization", getAuthorizationHeader(basicAuthClientId, basicAuthClientSecret));

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(this.baseUaaZoneUrl + "/check_token", HttpMethod.POST, new HttpEntity<>(tokenFormData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        logger.info("check token response: " + checkTokenResponse.getBody());
    }

    private String getAuthorizationHeader(String username, String password) {
        String credentials = String.format("%s:%s", username, password);
        return String.format("Basic %s", new String(Base64.encode(credentials.getBytes())));
    }

    @SuppressWarnings("unchecked")
    private void assertAccessToken(final OAuth2AccessToken accessToken) {
        Jwt decodedToken = JwtHelper.decode(accessToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        List<String> scopes = (List<String>) claims.get(ClaimConstants.SCOPE);
        Assert.assertTrue(scopes.contains(CONFIGURED_SCOPE));
        assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.SUB));
        assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.CLIENT_ID));
        assertEquals(GRANT_TYPE_JWT_BEARER, claims.get(ClaimConstants.GRANT_TYPE));
        assertEquals(this.baseUaaZoneUrl + "/oauth/token", claims.get(ClaimConstants.ISS));
        long currentTimestamp = System.currentTimeMillis() / 1000;
        String expirationTimestamp = (claims.get(ClaimConstants.EXPIRY_IN_SECONDS)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        Assert.assertTrue(Long.parseLong(expirationTimestamp) > currentTimestamp);
        Assert.assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
    }
}