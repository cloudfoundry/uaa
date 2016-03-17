package org.cloudfoundry.identity.uaa.integration.feature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.OauthGrant;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.token.MockAssertionToken;
import org.cloudfoundry.identity.uaa.provider.token.TestKeys;
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
    
    static final String HEADER_SIGNING_KEY = "MIIEogIBAAKCAQEAhxvEgeHTQJ0JLiQY5UHmsSSEc0Jt3rRLOcQbVviAjOh/VT7V"
            + "HWlIHqXU5t6thbpUbjtPs818UEXQO85iuWI8Tp5CRuYnRFQAoGAM7V0kIwOUGwXh"
            + "OgZBY7BQ+I+O3MFQn4nFp8z5u522RbFg+aNNQCLyXZLizdRDVDvfKih/D1nnNUO1"
            + "9bj9wdZ32MvpKDW2lmMk5Zkq0BVwSyXEvn/wTSlBr2nDRhTNPuk+JFawgZQosNRf"
            + "dh1ElEJm3tge81JSUg/NLPsCADUWmtRohaVhIGdpqS0APywO3xdGz73UY4xkFtqa"
            + "aKp1vDXw9ljHUkaZyPswnKu8SErvGdTvIDbKfQIDAQABAoIBAAU1peMYMQwZwgPc"
            + "cnVMkDeeX9kN46ylqQzmKeO1m0dTo61GyfLjX1uHK2lnhqtUXvMNKGqXbsatmnTj"
            + "5VyelBK3+XhAYZ052/hTG8x/Peh3t9s+48tX+Gd+ofCjoG+UqKYuKsfomGyKjT+s"
            + "sj+N82mYr126TzJ+j8YMtPMsMpIF6AhZPT/WJTimDktlp20oVYFXsNxGuLecaWzl"
            + "ZRwfRrUuN495PE2fQx1WCWl5rHJbYxgyeQwtm18ksHRRxpqK2/uj1LGM54s0+Deg"
            + "gWDBIjrNSd5PQWqTh+xz5qZajAO2dAcbz2PzWkJjuC7qXAmVUyWjJXDHV6Re+DQJ"
            + "r+DIqiECgYEAyTru23IU4TV/madjuWyuBK1hEZTriOzt/lOlH1ETNzpQWMnq7qDZ"
            + "ovPI10KD86BkfjJORNIQX3VeWw1//htJqsEVyma4KnDzxcvp5a63NIYzE/YIp8z7"
            + "aaTv4x0Jik+ULlaYIpyFKAI5hUrY4rvNC8rZCQO+8joyRGjRPLehnWUCgYEAq+Gv"
            + "xARCcmAKY0NX5OL2WuvTJncdk3fbqikPLtjfA2LJB+1q/09ENUZzf4yD1BNZdaeY"
            + "uDTz6wWO439DXk3oLvYzNwJ6Py8qRrfynXTqbXHVChCif8UQRzeJpVGILxq1raPp"
            + "EMsooB1El/pCtXyA+jD1knuReFSLFZGE+MS3UzkCgYAueY3w4Mgxu0ldE2vUx2Tp"
            + "b6GbjelYFmBg/LCGKxNlDfLAjuHTexLIr8US8inHeqO7AaNSAbIGWfUQ0m1dIrBA"
            + "35dIx7CBHNUwOYgro85sMxJY6dnV52GpZI6CxZIOf5KZoSZB2CRouRrPzhmJRBZ3"
            + "QsIdcuAG0aoKYqrwevi4gQKBgH5yUJD+pTdpShsOTtn20k+/D55LoPl9Ap/jBuVq"
            + "7F2cTdJEKiPa143t30glQlJBTd3NRv+1DQCIHT9lv1TgMYBi5PiCHRbghtRxvM1z"
            + "VobfaF+4LyOaAMizpdJ18Z7domw0mmAdZSyte2nm1S6YgnYMkIyL1U/VumBKpq0w"
            + "YsGZAoGACqVEK6LXrfhcVRhScD51tYzv/dqimVezZw4YeeW7iRkydfRmf7QW16CO"
            + "4qbzfoDM8RP0bsRaxtkxPi1wic/CsN7iyYsLKC1KOhg9NiYrfiX4gcYHC/PEGK8x"
            + "3upYUhE4xaReJ0wKBFVWOeQZjHW+RZMxDf7RHv71f7SFN87YNGY=";

    private static final String PREDIX_CLIENT_ASSERTION_HEADER = "Predix-Client-Assertion";
    private static final String ASSERTION = "assertion";
    private static final String CONFIGURED_SCOPE = "machine.m1.admin";
    private static final String TENANT_ID = "t10";
    private static final String ISSUER_ID = "d10";
    private static final String AUDIENCE = "http://localhost:8080/uaa/oauth/token";
    private static final String PLAIN_TEXT =TENANT_ID + ":" + ISSUER_ID;

    @Value("${integration.test.base_url}")
    private String baseUrl;

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    ServerRunning serverRunning = ServerRunning.isRunning();

    private OAuth2RestTemplate adminClient;

    private RestTemplate tokenRestTemplate = new RestTemplate();

    private static HttpHeaders headers;

    private static PrivateKey privateKey;

    @BeforeClass
    public static void setup() throws Exception {
        headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        List<MediaType> acceptMediaTypes = new ArrayList<MediaType>();
        acceptMediaTypes.add(MediaType.APPLICATION_JSON);
        headers.setAccept(acceptMediaTypes);
        privateKey = getPrivateKey(HEADER_SIGNING_KEY);
    }

    private void createTestMachineClient() throws Exception {
        // register client for jwt-bearer grant
        this.adminClient = (OAuth2RestTemplate) IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(this.baseUrl, new String[0], "admin", "adminsecret"));
        BaseClientDetails client = new BaseClientDetails(ISSUER_ID, "none", "uaa.none", OauthGrant.JWT_BEARER,
                CONFIGURED_SCOPE, null);
        IntegrationTestUtils.createClient(adminClient.getAccessToken().getValue(), baseUrl, client);
    }

    @Test
    public void testJwtBearerGrantForUnknownClient() {
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);

        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("authz grant with unknown client did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void testJwtBearerGrantWrongGrantType() throws Exception {
        createTestMachineClient();
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.CLIENT_CREDENTIALS);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
        IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
    }

    @Test
    public void testJwtBearerGrantNoAssertionTokenWithBasicAuth() throws Exception {
        createTestMachineClient();
        String clientCreds = "admin:adminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            headers.remove("Authorization");
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantEmptyAssertionToken() throws Exception {
        createTestMachineClient();
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, "");
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantNoAssertionToken() throws Exception {
        createTestMachineClient();
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantAndClientGrantSuccess() throws Exception {
        createTestMachineClient();
        String clientCreds = "admin:adminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        // verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        assertAccessToken(accessToken);
        headers.remove("Authorization");
        IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
    }

    @Test
    public void testJwtBearerGrantAndClientGrantWithBadCreds() throws Exception {
        createTestMachineClient();
        String clientCreds = "notaadmin:notaadminsecret";
        String base64ClientCreds = Base64.getEncoder().encodeToString(clientCreds.getBytes());
        headers.add("Authorization", "Basic " + base64ClientCreds);
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);
        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            headers.remove("Authorization");
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantSuccess() throws Exception {
        createTestMachineClient();
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, getPredixAssertionHeaderValue(PLAIN_TEXT, privateKey));
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        ResponseEntity<OAuth2AccessToken> response = this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token",
                requestEntity, OAuth2AccessToken.class);
        // verify access token received
        OAuth2AccessToken accessToken = response.getBody();
        assertAccessToken(accessToken);
        headers.remove(PREDIX_CLIENT_ASSERTION_HEADER);
        IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
    }

    @Test
    public void testJwtBearerGrantNoDeviceHeader() throws Exception {
        createTestMachineClient();
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);
        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantEmptyDeviceHeader() throws Exception {
        createTestMachineClient();
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, "");
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            headers.remove(PREDIX_CLIENT_ASSERTION_HEADER);
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    @Test
    public void testJwtBearerGrantIncorrectlySignedDeviceHeader() throws Exception {
        createTestMachineClient();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair differentKeyPair = keyGen.generateKeyPair();
        headers.add(PREDIX_CLIENT_ASSERTION_HEADER, getPredixAssertionHeaderValue(PLAIN_TEXT, differentKeyPair.getPrivate()));
        // create bearer token
        String token = new MockAssertionToken().mockAssertionToken(ISSUER_ID, System.currentTimeMillis() - 240000, 600,
                TENANT_ID, AUDIENCE);
        // call uaa/oauth/token
        LinkedMultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add(OAuth2Utils.GRANT_TYPE, OauthGrant.JWT_BEARER);
        formData.add(ASSERTION, token);

        HttpEntity<LinkedMultiValueMap<String, String>> requestEntity = new HttpEntity<>(formData, headers);

        try {
            this.tokenRestTemplate.postForEntity(baseUrl + "/oauth/token", requestEntity, String.class);
            Assert.fail("jwt bearer grant flow with incorrect grant type did not fail.");
        } catch (HttpClientErrorException e) {
            Assert.assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        } finally {
            headers.remove(PREDIX_CLIENT_ASSERTION_HEADER);
            IntegrationTestUtils.deleteClient(this.adminClient, baseUrl, ISSUER_ID);
        }
    }

    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(HEADER_SIGNING_KEY.getBytes());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private String getPredixAssertionHeaderValue(String plainText, PrivateKey privateKey) throws Exception {
        byte[] encodedPlainText = Base64.getEncoder().encode((TENANT_ID + ":" + ISSUER_ID).getBytes());
        return encodedPlainText
                + getMockHeaderSignature(plainText, privateKey).toString();
    }

    private byte[] getMockHeaderSignature(String plainTextHeader, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(plainTextHeader.getBytes("UTF-8"));
        return Base64.getEncoder().encode(sig.sign());
    }

    private void assertAccessToken(OAuth2AccessToken accessToken) {
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
        long currentTimestamp = System.currentTimeMillis() / 1000;
        String exparationTimestamp = (claims.get(ClaimConstants.EXP)).toString();
        String issueTimestamp = (claims.get(ClaimConstants.IAT)).toString();
        Assert.assertTrue(Long.parseLong(exparationTimestamp) > currentTimestamp);
        Assert.assertTrue(Long.parseLong(issueTimestamp) <= currentTimestamp);
        Assert.assertEquals("bearer", accessToken.getTokenType());
        Assert.assertFalse(accessToken.isExpired());
    }
}