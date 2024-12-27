package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class UserTokenGrantIT {

    @Autowired
    @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    @Autowired
    TestAccounts testAccounts;

    final String user_token_id = "oauth_showcase_user_token";
    final String user_token_secret = "secret";
    final String user_token_public_id = "oauth_showcase_user_token_public";
    final String empty_string = "";

    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl + "/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void testExchangeFromConfidentialClientWithCfClientWithEmptySecret() {
        // Given Create password token from confidential client
        String token = getPasswordGrantToken(user_token_id, user_token_secret);

        // When do user_token grant flow using public cf client (public, because of empty secret)
        String newToken = doUserTokenGrant("cf", token, HttpStatus.OK);

        // Then validation expected result
        assertNotNull(newToken);
        checkRefreshToken(newToken);
    }

    @Test
    public void testExchangeFromConfidentialClientWithConfidentialClient() {
        // Given Create password token from confidential client
        String token = getPasswordGrantToken(user_token_id, user_token_secret);

        // When do user_token grant flow using confidential oauth_showcase_user_token client
        String newToken = doUserTokenGrant(user_token_id, token, HttpStatus.OK);

        // Then validation expected result
        checkRefreshToken(newToken);
    }

    @Test
    public void testExchangeFromPublicClientWithPublicClient() {
        // Given Create password token from public client
        String token = getPasswordGrantToken(user_token_public_id, empty_string);

        // When do user_token grant flow using public client
        String newToken = doUserTokenGrant(user_token_public_id, token, HttpStatus.OK);

        // Then validation expected result
        checkRefreshToken(newToken);
    }

    @Test
    public void testExchangeFromPublicClientWithConfidentialClient() {
        // Given Create password token from public client
        String token = getPasswordGrantToken(user_token_public_id, empty_string);

        // When do user_token grant flow using confidential oauth_showcase_user_token client
        String newToken = doUserTokenGrant(user_token_id, token, HttpStatus.OK);

        // Then validation expected result
        checkRefreshToken(newToken);
    }

    @Test
    public void testExchangeFromConfidentialClientWithAdminClientExpectUnauthorized() {
        // Given Create password token from public client
        String token = getPasswordGrantToken(user_token_id, user_token_secret);

        // When do user_token grant flow using admin client
        doUserTokenGrant("admin", token, HttpStatus.UNAUTHORIZED);
    }

    private String getPasswordGrantToken(String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader(clientId, clientSecret));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());

        ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
                Map.class);

        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
        return (String) responseEntity.getBody().get("access_token");
    }

    private String doUserTokenGrant(String clientId, String token, HttpStatus expectedStatus) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", " Bearer " + token);

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", clientId);
        postBody.add("token_format", "jwt");
        postBody.add("response_type", "token");
        postBody.add("grant_type", "user_token");
        ResponseEntity<Map> responseEntity = null;
        HttpStatus responseStatus;

        try {
            responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers), Map.class);
            responseStatus = responseEntity.getStatusCode();
        } catch (HttpClientErrorException clientErrorException) {
            responseStatus = clientErrorException.getStatusCode();
        }
        assertEquals(expectedStatus, responseStatus);

        if (expectedStatus == HttpStatus.OK) {
            Map<String, Object> params = responseEntity.getBody();
            return (String) params.get("refresh_token");
        } else {
            return null;
        }
    }

    private void checkRefreshToken(String token) {
        assertNotNull(token);
        assertEquals(34, token.length());
        assertTrue(token.endsWith("-r"));
    }
}
