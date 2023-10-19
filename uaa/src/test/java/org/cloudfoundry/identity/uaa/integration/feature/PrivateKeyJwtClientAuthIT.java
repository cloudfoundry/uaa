package org.cloudfoundry.identity.uaa.integration.feature;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
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
import org.springframework.security.jwt.Jwt;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class PrivateKeyJwtClientAuthIT {

  //jwt.token.signing-key from uaa.yml
  @Value("${integration.test.signing-key}")
  private String jwtTokenSigningKey;

  @Autowired
  @Rule
  public IntegrationTestRule integrationTestRule;

  @Autowired
  WebDriver webDriver;

  @Value("${integration.test.base_url}")
  String baseUrl;

  @Autowired
  TestAccounts testAccounts;

  @Autowired
  TestClient testClient;

  @Autowired
  RestOperations restOperations;

  @Test
  public void testPasswordGrantWithClientUsingPrivateKeyJwtAndExpectValidToken() {
    // Given, client with jwks trusted keys
    String usedClientId = "client_with_jwks_trust";
    Map<String, Object> expectedClaims = Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "origin", "uaa",
        "zid", "uaa",
        "user_name", testAccounts.getUserName(),
        "grant_type", "password"
    );
    // When
    String accessToken = getPasswordGrantToken(usedClientId, "access_token", OK);
    // Then
    assertNotNull(accessToken);
    assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(expectedClaims);
  }

  @Test
  public void testClientCredentialGrantWithClientUsingPrivateKeyJwtAndExpectValidToken() {
    // Given, client with jwks trusted keys
    String usedClientId = "client_with_jwks_trust";
    Map<String, Object> expectedClaims = Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "zid", "uaa",
        "grant_type", "client_credentials"
    );
    // When
    String accessToken = getClientCredentialsGrantToken(usedClientId, "access_token", OK);
    // Then
    assertNotNull(accessToken);
    assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(expectedClaims);
    assertThat(getTokenClaims(accessToken)).doesNotContainKeys("user_name", "origin");
  }

  @Test
  public void testClientCredentialGrantWithClientUsingPrivateKeyJwtUriAndExpectValidToken() {
    // Given, client with jwks_uri keys
    String usedClientId = "client_with_allowpublic_and_jwks_uri_trust";
    Map<String, Object> expectedClaims = Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "zid", "uaa",
        "grant_type", "client_credentials"
    );
    // When
    String accessToken = getClientCredentialsGrantToken(usedClientId, "access_token", OK);
    // Then
    assertNotNull(accessToken);
    assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(expectedClaims);
    assertThat(getTokenClaims(accessToken)).doesNotContainKeys("user_name", "origin");
  }

  @Test
  public void testRefreshAfterPasswordWithClientUsingPrivateKeyJwtUriAndExpectValidToken() {
    // Given, client with jwks_uri keys
    String usedClientId = "client_with_allowpublic_and_jwks_uri_trust";
    Map<String, Object> expectedClaims = Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "origin", "uaa",
        "zid", "uaa",
        "user_name", testAccounts.getUserName(),
        "grant_type", "password"
    );
    // When
    String refreshToken = getPasswordGrantToken(usedClientId, "refresh_token", OK);
    // Then
    assertNotNull(refreshToken);
    // When
    String accessToken = getRefreshGrantToken(usedClientId, refreshToken, "access_token", OK);
    // Then
    assertNotNull(accessToken);
    assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(expectedClaims);
  }

  @Test
  public void testJwtBearerAfterPasswordWithClientUsingPrivateKeyJwtUriAndExpectValidToken() {
    // Given, client with jwks_uri keys
    String usedClientId = "client_with_allowpublic_and_jwks_uri_trust";
    Map<String, Object> expectedClaims = Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "origin", "uaa",
        "zid", "uaa",
        "user_name", testAccounts.getUserName(),
        "grant_type", "password"
    );
    // When
    String passwordToken = getPasswordGrantToken(usedClientId, "access_token", OK);
    // Then
    assertNotNull(passwordToken);
    assertThat(getTokenClaims(passwordToken)).containsAllEntriesOf(expectedClaims);
    // When
    String accessToken = getJwtBearerGrantToken(usedClientId, passwordToken, "access_token", OK);
    // Then
    assertNotNull(accessToken);
    assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "origin", "uaa",
        "zid", "uaa",
        "user_name", testAccounts.getUserName(),
        "grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ));
  }

  @Test
  public void testPasswordGrantWithClientUsingOidcProxyAndExpectValidToken() throws Exception {
    // Given
    String usedClientId = "client_with_allowpublic_and_jwks_uri_trust";
    String expectedOriginKey = "oidc-proxy";
    Map<String, Object> expectedClaims = Map.of(
        "client_auth_method", "private_key_jwt",
        "client_id", usedClientId,
        "origin", expectedOriginKey,
        "zid", "uaa",
        "user_name", testAccounts.getUserName(),
        "grant_type", "password"
    );
    String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
    try {
      // create OIDC IdP using private_key_jwt with jwks trust
      IdentityProvider oidcProxy = createOidcProviderTemplate("client_with_jwks_trust", expectedOriginKey);
      IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, oidcProxy);
      // When Password Grant with OIDC proxy in between
      String accessToken = getPasswordProxyGrantToken(usedClientId, "access_token", expectedOriginKey, OK);
      // Then
      assertNotNull(accessToken);
      assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(expectedClaims);
    } finally {
      IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, "uaa", expectedOriginKey);
    }
  }

  @Test
  public void testAutorizationCodeGrantWithClientUsingOidcProxyAndExpectValidToken() throws Exception {
    // Given
    String expectedOriginKey = "oidc-proxy-private-key-jwt";
    String usedClientId = "client_with_allowpublic_and_jwks_uri_trust";
    String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
    try {
      // create OIDC IdP using private_key_jwt with jwks trust
      IdentityProvider oidcProxy = createOidcProviderTemplate("client_with_jwks_trust", expectedOriginKey);
      IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, oidcProxy);
      ServerRunning serverRunning = ServerRunning.isRunning();
      serverRunning.setHostName("localhost");
      // login
      String accessToken = IntegrationTestUtils.getAuthorizationCodeToken(
          serverRunning,
          usedClientId,
          testClient.createClientJwt(usedClientId, jwtTokenSigningKey),
          testAccounts.getUserName(),
          testAccounts.getPassword(),
          null,
          baseUrl + "/login/callback/" + expectedOriginKey,
          expectedOriginKey,
          false);
      assertThat(getTokenClaims(accessToken)).containsAllEntriesOf(Map.of(
          "client_auth_method", "private_key_jwt",
          "client_id", usedClientId,
          "origin", "uaa",
          "zid", "uaa",
          "user_name", testAccounts.getUserName(),
          "grant_type", "authorization_code"
      ));
    } finally {
      IntegrationTestUtils.deleteProvider(clientCredentialsToken, baseUrl, "uaa", expectedOriginKey);
    }
  }

  @Test
  public void testPasswordGrantWithClientUsingPrivateKeyJwtAndExpectClientError() {
    // When
    String response = getPasswordGrantToken("admin", "access_token", UNAUTHORIZED);
    // Then
    assertNotNull(response);
    assertThat(response).contains("401");
  }

  @Test
  public void testClientCredentialGrantWithClientUsingPrivateKeyJwtAndExpectClientError() {
    // When
    String response = getClientCredentialsGrantToken("any-other-not-existing-client", "access_token", UNAUTHORIZED);
    // Then
    assertNotNull(response);
    assertThat(response).contains("401");
  }

  private String getClientCredentialsGrantToken(String clientId, String returnToken, HttpStatus expected) {
    return getToken(clientId, returnToken, expected, "client_credentials", null, null, null, null);
  }

  private String getPasswordGrantToken(String clientId, String returnToken, HttpStatus expected) {
    return getToken(clientId, returnToken, expected, "password", testAccounts.getUserName(), testAccounts.getPassword(), null, null);
  }

  private String getPasswordProxyGrantToken(String clientId, String returnToken, String origin, HttpStatus expected) {
    return getToken(clientId, returnToken, expected, "password", testAccounts.getUserName(), testAccounts.getPassword(), "login_hint", "{\"origin\":\""+origin+"\"}");
  }

  private String getRefreshGrantToken(String clientId, String refreshTokenValue, String returnToken, HttpStatus expected) {
    return getToken(clientId, returnToken, expected, "refresh_token", null, null, "refresh_token", refreshTokenValue);
  }

  private String getJwtBearerGrantToken(String clientId, String bearerToken, String returnToken, HttpStatus expected) {
    return getToken(clientId, returnToken, expected, "urn:ietf:params:oauth:grant-type:jwt-bearer", null, null, "assertion", bearerToken);
  }

  private String getToken(String clientId, String returnToken, HttpStatus expected, String grantType, String userName, String password, String extraKey, String extraValue) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

    LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
    postBody.add("grant_type", grantType);
    if (userName != null) {
      postBody.add("username", userName);
    }
    if (password != null) {
      postBody.add("password", password);
    }
    if (extraKey != null && extraValue != null) {
      postBody.add(extraKey, extraValue);
    }
    postBody.add("token_format", "jwt");
    postBody.add(JwtClientAuthentication.CLIENT_ASSERTION, testClient.createClientJwt(clientId, jwtTokenSigningKey));
    postBody.add(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, JwtClientAuthentication.GRANT_TYPE);

    ResponseEntity<Map> responseEntity;
    try {
      responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers), Map.class);
    } catch (HttpClientErrorException e) {
      assertNotEquals("Expected OK, but the call failed", expected, OK);
      return e.getMessage();
    }
    assertEquals(expected, responseEntity.getStatusCode());
    if (expected == OK) {
      return (String) responseEntity.getBody().get(returnToken);
    } else {
      fail("not expected");
      return null;
    }
  }

  private static Map<String, Object> getTokenClaims(String token) {
    Jwt tokenClaims = JwtHelper.decode(token);
    return JsonUtils.readValue(tokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {});
  }

  private IdentityProvider createOidcProviderTemplate(String clientId, String origin) throws MalformedURLException {
    IdentityProvider identityProvider = new IdentityProvider<>();
    identityProvider.setName("my oidc provider");
    identityProvider.setIdentityZoneId(OriginKeys.UAA);
    OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
    config.setClientAuthInBody(false);
    config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
    config.addAttributeMapping("given_name", "email");
    config.addAttributeMapping("family_name", "email");
    config.addAttributeMapping("external_groups", "scope");
    config.setStoreCustomAttributes(true);
    config.addWhiteListedGroup("*");
    config.setAuthUrl(new URL(baseUrl + "/oauth/authorize"));
    config.setTokenUrl(new URL(baseUrl + "/oauth/token"));
    config.setTokenKeyUrl(new URL(baseUrl + "/token_key"));
    config.setIssuer(baseUrl + "/oauth/token");
    config.setUserInfoUrl(new URL(baseUrl + "/userinfo"));

    config.setShowLinkText(true);
    config.setLinkText("My OIDC Proxy Provider");
    config.setSkipSslValidation(true);
    config.setRelyingPartyId(clientId);
    config.setRelyingPartySecret(null);
    config.setJwtClientAuthentication(Boolean.TRUE);
    config.setPasswordGrantEnabled(true);
    List<String> requestedScopes = new ArrayList<>();
    requestedScopes.add("openid");
    requestedScopes.add("cloud_controller.read");
    config.setScopes(requestedScopes);
    identityProvider.setConfig(config);
    identityProvider.setOriginKey(origin);
    identityProvider.setIdentityZoneId("uaa");
    return identityProvider;
  }

}
