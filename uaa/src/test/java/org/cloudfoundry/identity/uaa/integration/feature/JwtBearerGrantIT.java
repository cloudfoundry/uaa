package org.cloudfoundry.identity.uaa.integration.feature;


import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantIT {

    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private static final String ISSUER_ID = "d10";
    private static final String INCORRECT_TENANT_ID = "t0";
    private static final String AUDIENCE =  "http://localhost:8080/uaa/oauth/token";

    @Value("${integration.test.base_url}")
    private String baseUrl;

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;
    
    ServerRunning serverRunning = ServerRunning.isRunning();
   
    private OAuth2RestTemplate adminClient;
    
    private RestTemplate tokenRestTemplate = new RestTemplate();
    
    private static HttpHeaders headers;
    
    @BeforeClass
    public static void setup() {
        headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        List<MediaType> acceptMediaTypes = new ArrayList<MediaType>();
        acceptMediaTypes.add(MediaType.APPLICATION_JSON);
        headers.setAccept(acceptMediaTypes);
    }

    private void createTestMachineClient() throws Exception {
        //register client for jwt-bearer grant
        this.adminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(this.baseUrl, new String[0], "admin", "adminsecret"));
        BaseClientDetails client = new BaseClientDetails(ISSUER_ID, "none","uaa.none", 
                OauthGrant.JWT_BEARER, CONFIGURED_SCOPE, null);
        IntegrationTestUtils.createClient(adminClient.getAccessToken().getValue(), baseUrl, client);
    }
    
    @Test
    public void testJwtBearerGrantForUnknownClient() {
        //create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, INCORRECT_TENANT_ID, AUDIENCE);
        
        //call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String,String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add("assertion", token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("authz grant with unknown client did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }
    
    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        createTestMachineClient();
        
        //create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000,
                600, TENANT_ID, AUDIENCE);
        //call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String,String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add("assertion", token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        
        ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        //verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        Jwt decodedToken = JwtHelper.decode(accessToken.getValue());
        Map<String, Object> claims = JsonUtils.readValue(decodedToken.getClaims(),
                new TypeReference<Map<String, Object>>() {
                    // Nothing to add here.
                });
        List<String> scopes = (List<String>) claims.get(ClaimConstants.SCOPE);
        Assert.assertTrue(scopes.contains(CONFIGURED_SCOPE));
        Assert.assertEquals(ISSUER_ID, claims.get(ClaimConstants.SUB));
        Assert.assertEquals(ISSUER_ID, claims.get(ClaimConstants.CLIENT_ID));
        Assert.assertEquals(OauthGrant.JWT_BEARER, claims.get(ClaimConstants.GRANT_TYPE));
        Assert.assertEquals("http://localhost:8080/uaa/oauth/token", claims.get(ClaimConstants.ISS));
        long currentTimestamp = System.currentTimeMillis()/1000;
        String exparationTimestamp = (claims.get(ClaimConstants.EXP)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        Assert.assertTrue(Long.parseLong(exparationTimestamp) > currentTimestamp);
        Assert.assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        Assert.assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
        
        IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
    }
}