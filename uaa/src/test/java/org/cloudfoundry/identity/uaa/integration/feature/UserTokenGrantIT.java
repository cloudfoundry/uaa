package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.After;
import org.junit.Assert;
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
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestOperations;

import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;

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
  public void testFlowFromConfidentialClientWithPublicCfClient() {
    // Create password token from confidential client
    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader(user_token_id, user_token_secret));

    LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
    postBody.add("grant_type", "password");
    postBody.add("username", testAccounts.getUserName());
    postBody.add("password", testAccounts.getPassword());

    ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
        Map.class);

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    String token = (String)responseEntity.getBody().get("access_token");

    // do password grant flow using public cf client
    String newToken = doUserTokenGrant("cf", token);
    Assert.assertNotNull(newToken);
  }

  @Test
  public void testFlowFromConfidentialClientWithConfidentialClient() {
    // Create password token from confidential oauth_showcase_user_token client
    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader(user_token_id, user_token_secret));

    LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
    postBody.add("grant_type", "password");
    postBody.add("username", testAccounts.getUserName());
    postBody.add("password", testAccounts.getPassword());

    ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
        Map.class);

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    String token = (String)responseEntity.getBody().get("access_token");

    // do password grant flow using confidential oauth_showcase_user_token client
    String newToken = doUserTokenGrant(user_token_id, token);
    Assert.assertNotNull(newToken);
  }

  @Test
  public void testFlowFromPublicClientWithPublicCfClient() {
    // Create password token from public client
    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("oauth_showcase_user_token_public", ""));

    LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
    postBody.add("grant_type", "password");
    postBody.add("username", testAccounts.getUserName());
    postBody.add("password", testAccounts.getPassword());

    ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
        Map.class);

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    String token = (String)responseEntity.getBody().get("access_token");

    // do password grant flow using public cf client
    String newToken = doUserTokenGrant("cf", token);
    Assert.assertNotNull(newToken);
  }

  @Test
  public void testFlowFromPublicClientWithConfidentialClient() {
    // Create password token from public client
    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader("oauth_showcase_user_token_public", ""));

    LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
    postBody.add("grant_type", "password");
    postBody.add("username", testAccounts.getUserName());
    postBody.add("password", testAccounts.getPassword());

    ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
        Map.class);

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    String token = (String)responseEntity.getBody().get("access_token");

    // do password grant flow using confidential oauth_showcase_user_token client
    String newToken = doUserTokenGrant(user_token_id, token);
    Assert.assertNotNull(newToken);
  }

  private String doUserTokenGrant(String clientId, String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    headers.add("Authorization", " Bearer " + token);

    LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
    postBody.add("client_id", clientId);
    postBody.add("token_format", "jwt");
    postBody.add("response_type", "token");
    postBody.add("grant_type", "user_token");
    ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
        Map.class);

    assertEquals(HttpStatus.OK, responseEntity.getStatusCode());

    Map<String, Object> params = responseEntity.getBody();
    return (String) params.get("refresh_token");
  }
}
