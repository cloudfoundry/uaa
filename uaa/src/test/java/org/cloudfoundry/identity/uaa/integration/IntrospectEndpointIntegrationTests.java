package org.cloudfoundry.identity.uaa.integration;

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.junit.Assert.*;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class IntrospectEndpointIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Test
    public void testDecodeToken() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        BasicCookieStore cookies = new BasicCookieStore();

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("state", "mystateid").queryParam("client_id", resource.getClientId())
                .queryParam("redirect_uri", resource.getPreEstablishedRedirectUri()).build();
        ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), getHeaders(cookies));
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), getHeaders(cookies));
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength + 1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            formData.add(USER_OAUTH_APPROVAL, "true");
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        } else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        assertTrue("Wrong location: " + location,
                location.matches(resource.getPreEstablishedRedirectUri() + ".*code=.+"));

        formData.clear();
        formData.add("client_id", resource.getClientId());
        formData.add("redirect_uri", resource.getPreEstablishedRedirectUri());
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(introspectResponse.getBody());

        HttpHeaders headers = new HttpHeaders();
        formData = new LinkedMultiValueMap<>();
        headers.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        introspectResponse = serverRunning.postForMap("/introspect", formData, headers);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));

        // Test that Spring's default converter can create an auth from the response.
        Authentication auth = (new DefaultUserAuthenticationConverter()).extractAuthentication(map);
    }

    @Test
    public void testUnauthorized() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/introspect", formData, headers);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertTrue(map.containsKey("error"));
    }

    @Test
    public void testForbidden() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", testAccounts.getAuthorizationHeader("cf", ""));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/introspect", formData, headers);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertTrue(map.containsKey("error"));
    }

    @Test
    public void testTokenWithoutAppResourceAuthority() {
        OAuth2AccessToken accessToken = getAdminToken();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();

        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "app", "appclientsecret");

        tokenHeaders.set("Authorization", "Bearer " + accessToken);
        formData.add("token", clientCredentialsToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.FORBIDDEN, introspectResponse.getStatusCode());
    }

    @Test
    public void testValidPasswordGrant_ClientSecretAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());
        assertNotNull(introspectResponse.getBody());
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));
    }

    @Test
    public void testValidPasswordGrant_ClientSecretAuthWithSpecialCharacters() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader("appspecial", "appclient|secret!"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());
        assertNotNull(introspectResponse.getBody());
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));
    }

    @Test
    public void testValidPasswordGrant_ClientTokenAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "app", "appclientsecret");
        tokenHeaders.set("Authorization", "Bearer " + clientCredentialsToken);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());
        assertNotNull(introspectResponse.getBody());
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));
    }

    @Test
    public void testValidPasswordGrant_ClientTokenAuthWithSpecialCharacters() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "appspecial", "appclient|secret!");
        tokenHeaders.set("Authorization", "Bearer " + clientCredentialsToken);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());
        assertNotNull(introspectResponse.getBody());
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));
    }

    @Test
    public void testValidPasswordGrant_ValidClientTokenAndInvalidBasicAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "app", "appclientsecret");
        tokenHeaders.add("Authorization", "Bearer " + clientCredentialsToken);
        tokenHeaders.add("Authorization", testAccounts.getAuthorizationHeader("app", "badpassword"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());
        assertNotNull(introspectResponse.getBody());
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));
    }

    @Test
    public void testValidPasswordGrant_InValidClientTokenAndValidBasicAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", "Bearer not-a-real-client-token");
        tokenHeaders.add("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.UNAUTHORIZED, introspectResponse.getStatusCode());
    }

    @Test
    public void testValidPasswordGrant_ValidClientTokenWithoutAppResourceAndValidBasicAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "notifications", "notificationssecret");
        tokenHeaders.add("Authorization", "Bearer " + clientCredentialsToken);
        tokenHeaders.add("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.FORBIDDEN, introspectResponse.getStatusCode());
    }

    @Test
    public void testValidPasswordGrant_RequiresClientCredentialsToken() {
        final String adminClientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("clientIdWithUaaResourceScope");
        clientDetails.setClientSecret("secret");
        clientDetails.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        clientDetails.setScope(Collections.singleton("uaa.resource"));
        clientDetails.setAuthorizedGrantTypes(Collections.singleton("password"));

        IntegrationTestUtils.createClient(adminClientCredentialsToken, baseUrl, clientDetails);

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret")
        );

        String username = UUID.randomUUID().toString();

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        scimUser.setPassword("password");
        scimUser.setPrimaryEmail("email@example.com");

        scimUser = IntegrationTestUtils.createUser(adminClientCredentialsToken, baseUrl, scimUser, null);
        ScimGroup uaaResourceGroup = IntegrationTestUtils.getGroup(adminClientCredentialsToken, null, baseUrl, "uaa.resource");
        IntegrationTestUtils.addMemberToGroup(adminClient, baseUrl, scimUser.getId(), uaaResourceGroup.getId());

        String userAccessTokenWithAppResource = DefaultOAuth2AccessToken.valueOf(
                IntegrationTestUtils.getPasswordToken(
                        baseUrl,
                        "clientIdWithUaaResourceScope",
                        "secret",
                        username,
                        "password",
                        "uaa.resource")).getValue();

        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", "Bearer " + userAccessTokenWithAppResource);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", userAccessTokenWithAppResource);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.FORBIDDEN, introspectResponse.getStatusCode());
    }

    @Test
    public void testAddidionalAttributes() {
        String accessToken = getUserToken("{\"az_attr\":{\"external_group\":\"domain\\\\group1\",\"external_id\":\"abcd1234\"}}");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());
        assertNotNull(introspectResponse.getBody());
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNotNull(map.get("iss"));
        assertEquals(testAccounts.getUserName(), map.get("user_name"));
        assertEquals(testAccounts.getEmail(), map.get("email"));
        assertEquals(true, map.get("active"));
    }

    @Test
    public void testInvalidAddidionalAttributes() {
        String accessToken = getUserToken("{\"az_attr\":{\"external_group\":true,\"external_id\":{\"nested_group\":true,\"nested_id\":1234}} }");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, introspectResponse.getStatusCode());

        @SuppressWarnings("unchecked")
        Map<String, String> map = introspectResponse.getBody();
        assertNull(map.get("az_attr"));
        assertEquals(true, map.get("active"));
    }

    @SuppressWarnings("unchecked")
    private OAuth2AccessToken getAdminToken() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.set("client_id", testAccounts.getAdminClientId());
        formData.set("client_secret", testAccounts.getAdminClientSecret());
        formData.set("response_type", "token");
        formData.set("grant_type", "client_credentials");

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        return DefaultOAuth2AccessToken.valueOf(response.getBody());
    }

    @SuppressWarnings("unchecked")
    private String getUserToken(String optAdditionAttributes) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.set("client_id", "cf");
        formData.set("client_secret", "");
        formData.set("username", testAccounts.getUserName());
        formData.set("password", testAccounts.getPassword());
        formData.set("response_type", "token");
        formData.set("grant_type", "password");
        formData.set("token_format", "jwt");
        if (optAdditionAttributes != null) {
            formData.set("authorities", optAdditionAttributes);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        return DefaultOAuth2AccessToken.valueOf(response.getBody()).getValue();
    }
}
