package org.cloudfoundry.identity.uaa.integration.feature;

import static org.junit.Assert.assertEquals;

import java.net.URI;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.KeyProviderConfig;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.provider.token.MockClientAssertionHeader;
import org.cloudfoundry.identity.uaa.provider.token.MockKeyProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.type.TypeReference;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class JwtBearerGrantIT {

    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final String ASSERTION = "assertion";
    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private final static String DEVICE_ID = "d10";
    private final static String DEVICE_CLIENT_ID = "c1";
    private static final String AUDIENCE = "http://localhost:8080/uaa/oauth/token";
    //TODO fill out when DCS deploys multitenant
    private static final String DCS_TEST_INSTANCE_ID = "";

    @Value("${integration.test.base_url}")
    private String baseUrl;

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    ServerRunning serverRunning = ServerRunning.isRunning();

    private OAuth2RestTemplate adminClient;
    private final RestTemplate tokenRestTemplate = new RestTemplate();

    private HttpHeaders getHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        String assertionHeader = new MockClientAssertionHeader().mockSignedHeader(System.currentTimeMillis() / 1000,
                DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);
        return headers;
    }

    private void createUaaClientForDevice() throws Exception {
        createUaaClientForDevice(DEVICE_ID, this.baseUrl);
    }

    private void createUaaClientForDevice(String uaaUrl) throws Exception {
        createUaaClientForDevice(DEVICE_ID, uaaUrl);
    }

    private void createUaaClientForDevice(final String deviceId, final String uaaUrl) throws Exception {
        // register client for jwt-bearer grant
        this.adminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(uaaUrl, new String[0], "admin", "adminsecret"));
        BaseClientDetails client = new BaseClientDetails(DEVICE_CLIENT_ID, "none", "uaa.none", GRANT_TYPE_JWT_BEARER,
                CONFIGURED_SCOPE, null);
        // authorize device for test client
        client.addAdditionalInformation(ClientConstants.ALLOWED_DEVICE_ID, deviceId);
        IntegrationTestUtils.createClient(this.adminClient.getAccessToken().getValue(), this.baseUrl, client);
    }

    @Test
    public void testJwtBearerGrantForUnknownClient() {
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken("non-existent-client", DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("authz grant with unknown client did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void testJwtBearerGrantForUnauthorizedDeviceId() throws Exception {
        createUaaClientForDevice("unauthorized-device", this.baseUrl);
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, this.getHttpHeaders());

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("authz grant with unauthorized device did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Test
    public void testJwtBearerGrantWrongGrantType() throws Exception {
        createUaaClientForDevice();

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }
    


    @Test
    public void testJwtBearerGrantMissingGrantType() throws Exception {
        createUaaClientForDevice();

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with missing grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Test
    public void testJwtBearerGrantNoAssertionTokenWithBasicAuth() throws Exception {
        createUaaClientForDevice();

        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "admin:adminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Test
    public void testJwtBearerGrantEmptyAssertionToken() throws Exception {
        createUaaClientForDevice(); // create client assertion header

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, "");
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Test
    public void testJwtBearerGrantNoAssertionToken() throws Exception {
        createUaaClientForDevice();

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, getHttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Test
    public void testJwtBearerGrantAndClientGrantSuccess() throws Exception {
        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "admin:adminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        doJwtBearerGrantRequest(headers);
    }

    @Test
    public void testJwtBearerGrantAndClientGrantWithBadCreds() throws Exception {
        createUaaClientForDevice();
        HttpHeaders headers = getHttpHeaders();
        String clientCreds = "notaadmin:notaadminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID, 0, 600, TENANT_ID,
                AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        doJwtBearerGrantRequest(getHttpHeaders());
    }

    @Test
    @Ignore
    //TODO enable when DCS deploys multitenant
    public void testJwtBearerGrantSuccessZonifiedDCS() throws Exception {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        IdentityZone zone = IntegrationTestUtils.createZoneOrUpdateSubdomain(adminClient, this.baseUrl, "testzone1", "testzone1", config);
        String zoneUrl = baseUrl.replace("localhost", zone.getSubdomain() + ".localhost");
        BaseClientDetails zoneAdminClient = new BaseClientDetails();
        zoneAdminClient.setClientId("admin");
        zoneAdminClient.setClientSecret("adminsecret");
        IntegrationTestUtils.createClientAsZoneAdmin(adminClient.getAccessToken().getValue(), baseUrl, zone.getId(), zoneAdminClient);

        BaseClientDetails dcsClient = new BaseClientDetails();
        dcsClient.setClientId("dcsClient");
        dcsClient.setClientSecret("dcsisawesome");
        dcsClient.setAuthorities(Collections.singleton(new SimpleGrantedAuthority("pki.cert.key")));
        dcsClient.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
        IntegrationTestUtils.createClient(adminClient.getAccessToken().getValue(), zoneUrl, dcsClient);
        configureKeyProviderInZone(zoneUrl, zone.getId(), dcsClient.getClientId());

        doJwtBearerGrantRequest(getHttpHeaders(), zoneUrl, zoneAdminClient, new MockAssertionToken(MockKeyProvider.ZONE1_PRIVATE_KEY));
    }

    private void configureKeyProviderInZone(String zoneUrl, String zoneId, String dcsClientId) {
        adminClient.postForEntity(zoneUrl + "/identity-zones/" + zoneId + "/key-provider-config", new KeyProviderConfig(dcsClientId, DCS_TEST_INSTANCE_ID), KeyProviderConfig.class);
    }

    private void doJwtBearerGrantRequest(final HttpHeaders headers, final String uaaUrl, final BaseClientDetails client, MockAssertionToken assertionToken) throws Exception {
        createUaaClientForDevice(uaaUrl);

        // create bearer token
        String token = assertionToken.mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
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

        ResponseEntity<Map> checkTokenResponse = new RestTemplate().exchange(uaaUrl + "/check_token",
                HttpMethod.POST, new HttpEntity<>(tokenFormData, headers), Map.class);
        assertEquals(checkTokenResponse.getStatusCode(), HttpStatus.OK);
        IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
    }

    private void doJwtBearerGrantRequest(final HttpHeaders headers) throws Exception {
        BaseClientDetails appClient = new BaseClientDetails();
        appClient.setClientId("app");
        appClient.setClientSecret("appclientsecret");
        doJwtBearerGrantRequest(headers, this.baseUrl, appClient, new MockAssertionToken());
    }

    @Ignore
    @Test
    public void testJwtBearerGrantNoDeviceHeader() throws Exception {
        createUaaClientForDevice();

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, new HttpHeaders());
        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow without client assertion header did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Ignore
    @Test
    public void testJwtBearerGrantEmptyDeviceHeader() throws Exception {
        createUaaClientForDevice();

        HttpHeaders headers = new HttpHeaders();
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, "");

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with empty client assertion header did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
    }

    @Ignore
    @Test
    public void testJwtBearerGrantIncorrectlySignedDeviceHeader() throws Exception {
        createUaaClientForDevice();

        HttpHeaders headers = new HttpHeaders();
        String assertionHeader = new MockClientAssertionHeader().mockIncorrectlySignedHeader(DEVICE_ID, TENANT_ID);
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, assertionHeader);

        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(DEVICE_CLIENT_ID, DEVICE_ID,
                System.currentTimeMillis(), 600, TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(this.baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrently signed client assertion header did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, this.baseUrl, DEVICE_CLIENT_ID);
        }
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
        Assert.assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.SUB));
        Assert.assertEquals(DEVICE_CLIENT_ID, claims.get(ClaimConstants.CLIENT_ID));
        Assert.assertEquals(GRANT_TYPE_JWT_BEARER, claims.get(ClaimConstants.GRANT_TYPE));
        Assert.assertEquals("http://localhost:8080/uaa/oauth/token", claims.get(ClaimConstants.ISS));
        long currentTimestamp = System.currentTimeMillis() / 1000;
        String expirationTimestamp = (claims.get(ClaimConstants.EXPIRY_IN_SECONDS)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        Assert.assertTrue(Long.parseLong(expirationTimestamp) > currentTimestamp);
        Assert.assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        Assert.assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
    }
}