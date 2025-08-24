package org.cloudfoundry.identity.uaa.integration;

import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultUserAuthenticationConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class IntrospectEndpointIntegrationTests {
    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Test
    void decodeToken() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        BasicCookieStore cookies = new BasicCookieStore();

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
                .queryParam("state", "mystateid").queryParam("client_id", resource.getClientId())
                .queryParam("redirect_uri", resource.getPreEstablishedRedirectUri()).build();
        ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), getHeaders(cookies));
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = result.getHeaders().getLocation().toString();
        IntegrationTestUtils.extractCookies(result, cookies);

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        // should be directed to the login screen...
        assertThat(response.getBody()).contains("/login.do")
                .contains("username")
                .contains("password");
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", testAccounts.getUserName());
        formData.add("password", testAccounts.getPassword());
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        IntegrationTestUtils.extractCookies(result, cookies);

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertThat(response.getBody()).contains("<h1>Application Authorization</h1>");

            formData.clear();
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            formData.add(USER_OAUTH_APPROVAL, "true");
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = result.getHeaders().getLocation().toString();
        } else {
            // Token cached so no need for second approval
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = response.getHeaders().getLocation().toString();
        }
        assertThat(location).as("Wrong location: " + location).matches(resource.getPreEstablishedRedirectUri() + ".*code=.+");

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
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(introspectResponse.getBody());

        HttpHeaders headers = new HttpHeaders();
        formData = new LinkedMultiValueMap<>();
        headers.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken.getValue());

        introspectResponse = serverRunning.postForMap("/introspect", formData, headers);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail())
                .containsEntry("active", Boolean.TRUE);

        // Test that Spring's default converter can create an auth from the response.
        (new DefaultUserAuthenticationConverter()).extractAuthentication(map);
    }

    @Test
    void unauthorized() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/introspect", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertThat(map).containsKey("error");
    }

    @Test
    void forbidden() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("token", "FOO");
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", testAccounts.getAuthorizationHeader("cf", ""));
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/introspect", formData, headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        @SuppressWarnings("unchecked")
        Map<String, String> map = response.getBody();
        assertThat(map).containsKey("error");
    }

    @Test
    void tokenWithoutAppResourceAuthority() {
        OAuth2AccessToken accessToken = getAdminToken();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();

        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "app", "appclientsecret");

        tokenHeaders.set("Authorization", "Bearer " + accessToken);
        formData.add("token", clientCredentialsToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void validPasswordGrantClientSecretAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(introspectResponse.getBody()).isNotNull();
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
        assertThat((Boolean) map.get("active")).isEqualTo(Boolean.valueOf(true));
    }

    @Test
    void validPasswordGrantClientSecretAuthWithSpecialCharacters() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", testAccounts.getAuthorizationHeader("appspecial", "appclient|secret!"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(introspectResponse.getBody()).isNotNull();
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
        assertThat((Boolean) map.get("active")).isEqualTo(Boolean.valueOf(true));
    }

    @Test
    void validPasswordGrantClientTokenAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "app", "appclientsecret");
        tokenHeaders.set("Authorization", "Bearer " + clientCredentialsToken);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(introspectResponse.getBody()).isNotNull();
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
        assertThat((Boolean) map.get("active")).isEqualTo(Boolean.valueOf(true));
    }

    @Test
    void validPasswordGrantClientTokenAuthWithSpecialCharacters() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "appspecial", "appclient|secret!");
        tokenHeaders.set("Authorization", "Bearer " + clientCredentialsToken);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(introspectResponse.getBody()).isNotNull();
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
        assertThat((Boolean) map.get("active")).isEqualTo(Boolean.valueOf(true));
    }

    @Test
    void validPasswordGrantValidClientTokenAndInvalidBasicAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "app", "appclientsecret");
        tokenHeaders.add("Authorization", "Bearer " + clientCredentialsToken);
        tokenHeaders.add("Authorization", testAccounts.getAuthorizationHeader("app", "badpassword"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(introspectResponse.getBody()).isNotNull();
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
        assertThat((Boolean) map.get("active")).isEqualTo(Boolean.valueOf(true));
    }

    @Test
    void validPasswordGrantInValidClientTokenAndValidBasicAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization", "Bearer not-a-real-client-token");
        tokenHeaders.add("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validPasswordGrantValidClientTokenWithoutAppResourceAndValidBasicAuth() {
        HttpHeaders tokenHeaders = new HttpHeaders();
        final String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "notifications", "notificationssecret");
        tokenHeaders.add("Authorization", "Bearer " + clientCredentialsToken);
        tokenHeaders.add("Authorization", testAccounts.getAuthorizationHeader("app", "appclientsecret"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        String userAccessToken = getUserToken(null);
        formData.add("token", userAccessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void validPasswordGrantRequiresClientCredentialsToken() {
        final String adminClientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(serverRunning, "admin", "adminsecret");

        UaaClientDetails clientDetails = new UaaClientDetails();
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
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void addidionalAttributes() {
        String accessToken = getUserToken("{\"az_attr\":{\"external_group\":\"domain\\\\group1\",\"external_id\":\"abcd1234\"}}");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(introspectResponse.getBody()).isNotNull();
        System.out.println(introspectResponse.getBody());

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).containsKey("iss")
                .containsEntry("user_name", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
        assertThat((Boolean) map.get("active")).isEqualTo(Boolean.valueOf(true));
    }

    @Test
    void invalidAddidionalAttributes() {
        String accessToken = getUserToken("{\"az_attr\":{\"external_group\":true,\"external_id\":{\"nested_group\":true,\"nested_id\":1234}} }");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        HttpHeaders tokenHeaders = new HttpHeaders();
        ClientCredentialsResourceDetails resource = testAccounts.getClientCredentialsResource("app", null, "app", "appclientsecret");
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        formData.add("token", accessToken);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> introspectResponse = serverRunning.postForMap("/introspect", formData, tokenHeaders);
        assertThat(introspectResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        Map<String, Object> map = introspectResponse.getBody();
        assertThat(map).doesNotContainKey("az_attr")
                .containsEntry("active", true);
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
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

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
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        return DefaultOAuth2AccessToken.valueOf(response.getBody()).getValue();
    }
}
