package org.cloudfoundry.identity.uaa.acceptance;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.provider.token.MockClientAssertionHeader;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantAT {
    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final String ASSERTION = "assertion";
    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private final static String DEVICE_ID = "d10";
    private final static String DEVICE_CLIENT_ID = "c1";

    protected final static Logger logger = LoggerFactory.getLogger(JwtBearerGrantAT.class);

    @Value("${ACCEPTANCE_ZONE_URL:}")
    String acceptanceZoneUrl;

    @Value("${KEY_PROVIDER_SERVICE_URL:not-used}")
    String keyProviderServiceUrl;

    @Value("${TOKEN_ISSUER_URL:}")
    String tokenIssuerUrl;

    private OAuth2RestTemplate adminClientRestTemplate;
    private BaseClientDetails identityClient;
    private final RestTemplate tokenRestTemplate = new RestTemplate();

    String assertionTokenAudience;
    String acceptanceTokenIssuer;

    @Before
    public void beforeEachTest() throws Exception {
        Assume.assumeTrue(keyProviderServiceUrl != null &&
                keyProviderServiceUrl.trim().startsWith("http"));
        Assume.assumeTrue(acceptanceZoneUrl != null &&
                acceptanceZoneUrl.trim().startsWith("http"));

        this.adminClientRestTemplate = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(this.acceptanceZoneUrl, new String[0], "admin", "acceptance-test"));
        this.instantiateIdentityClient();
        this.assertionTokenAudience = this.acceptanceZoneUrl + "/oauth/token";

        if (this.tokenIssuerUrl.isEmpty()) {
            this.acceptanceTokenIssuer = this.acceptanceZoneUrl + "/oauth/token";
        } else {
            this.acceptanceTokenIssuer = this.tokenIssuerUrl;
        }

        createUaaClientForDevice(DEVICE_ID);
    }

    @After
    public void afterEachTest() throws Exception {
        IntegrationTestUtils.deleteClient(this.adminClientRestTemplate, this.acceptanceZoneUrl, this.DEVICE_CLIENT_ID);
    }

    private void instantiateIdentityClient() {
        this.identityClient = new BaseClientDetails();
        this.identityClient.setClientId("identity");
        this.identityClient.setClientSecret("identitysecret");
    }

    private HttpHeaders getHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        String assertionHeader = new MockClientAssertionHeader().mockSignedHeader(System.currentTimeMillis() / 1000,
                DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);
        return headers;
    }

    private void createUaaClientForDevice(final String deviceId) throws Exception {
        // register client for jwt-bearer grant
        BaseClientDetails client = new BaseClientDetails(DEVICE_CLIENT_ID, "none", "uaa.none", GRANT_TYPE_JWT_BEARER,
                CONFIGURED_SCOPE, null);
        // authorize device for test client
        client.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, deviceId);
        IntegrationTestUtils.createClient(this.adminClientRestTemplate.getAccessToken().getValue(), this.acceptanceZoneUrl, client);
    }

    @Test
    public void testJwtBearerGrantAndClientGrantSuccess() throws Exception {
        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "admin:acceptance-test";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        doJwtBearerGrantRequest(headers, this.acceptanceZoneUrl, this.identityClient, new MockAssertionToken());
    }

    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        doJwtBearerGrantRequest(getHttpHeaders(), this.acceptanceZoneUrl, this.identityClient, new MockAssertionToken());
    }

    private void doJwtBearerGrantRequest(final HttpHeaders headers, final String uaaUrl, final BaseClientDetails client, MockAssertionToken assertionToken) throws Exception {
        // create bearer token
        String token = assertionToken.mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                                                         System.currentTimeMillis(), 600, TENANT_ID, assertionTokenAudience);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        logger.info("<<<<<<<<<<<<<<<<<<<<Use JWT Grant to Exchange the token>>>>>>>>>>>>>"+token);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(uaaUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        // verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        assertAccessToken(accessToken);

        MultiValueMap<String, String> tokenFormData = new LinkedMultiValueMap<>();
        tokenFormData.add("token", accessToken.getValue());

        String clientCreds = client.getClientId() + ":" + client.getClientSecret();
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.set("Authorization", "Basic " + base64ClientCreds);

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(this.acceptanceZoneUrl + "/check_token",
                HttpMethod.POST, new HttpEntity<>(tokenFormData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
    }

    private void assertAccessToken(final OAuth2AccessToken accessToken) {
        Jwt decodedToken = JwtHelper.decode(accessToken.getValue());
        logger.info(accessToken.toString());
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        List<String> scopes = (List<String>) claims.get(ClaimConstants.SCOPE);
        Assert.assertTrue(scopes.contains(CONFIGURED_SCOPE));
        Assert.assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.SUB));
        Assert.assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.CLIENT_ID));
        Assert.assertEquals(GRANT_TYPE_JWT_BEARER, claims.get(ClaimConstants.GRANT_TYPE));
        Assert.assertEquals(this.acceptanceTokenIssuer, claims.get(ClaimConstants.ISS));
        long currentTimestamp = System.currentTimeMillis() / 1000;
        String expirationTimestamp = (claims.get(ClaimConstants.EXPIRY_IN_SECONDS)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        Assert.assertTrue(Long.parseLong(expirationTimestamp) > currentTimestamp);
        Assert.assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        Assert.assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
    }
}
