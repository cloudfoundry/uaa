/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration.feature;

import org.apache.commons.codec.binary.Base64;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
class OpenIdTokenGrantsIT {

    @Autowired
    TestAccounts testAccounts;

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    private RestTemplate client;

    private ScimUser user;
    private String secret = "secr3T";

    private String[] aud = {"scim", "openid", "cloud_controller", "password", "cf", "uaa"};
    private String[] openid = new String[]{"openid"};

    @BeforeEach
    void setUp() {
        ((RestTemplate) restOperations).setRequestFactory(new IntegrationTestUtils.StatelessRequestFactory());
        ClientCredentialsResourceDetails clientCredentials =
                getClientCredentialsResource(new String[]{"scim.write"}, testAccounts.getAdminClientId(), testAccounts.getAdminClientSecret());
        client = IntegrationTestUtils.getClientCredentialsTemplate(clientCredentials);
        user = createUser(new RandomValueStringGenerator().generate(), "openiduser", "openidlast", "test@openid,com", true);
    }

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    private ClientCredentialsResourceDetails getClientCredentialsResource(String[] scope, String clientId,
                                                                          String clientSecret) {
        return IntegrationTestUtils.getClientCredentialsResource(baseUrl, scope, clientId, clientSecret);
    }

    private ScimUser createUser(String username, String firstName, String lastName,
                                String email, boolean verified) {
        return IntegrationTestUtils.createUser(client, baseUrl, username, firstName, lastName, email, verified);
    }

    @Test
    void implicitGrant() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "cf");
        postBody.add("redirect_uri", "http://localhost:8080/redirect/cf");
        postBody.add("response_type", "token id_token");
        postBody.add("source", "credentials");
        postBody.add("username", user.getUserName());
        postBody.add("password", secret);

        ResponseEntity<Void> responseEntity = restOperations.exchange(
                baseUrl + "/oauth/authorize",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class
        );

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        UriComponents locationComponents = UriComponentsBuilder.fromUri(responseEntity.getHeaders().getLocation()).build();
        assertThat(locationComponents.getHost()).isEqualTo("localhost");
        assertThat(locationComponents.getPath()).isEqualTo("/redirect/cf");

        MultiValueMap<String, String> params = parseFragmentParams(locationComponents);

        assertThat(params.get("jti")).isNotEmpty();
        assertThat(params.getFirst("token_type")).isEqualTo("bearer");
        assertThat(Integer.parseInt(params.getFirst("expires_in"))).isGreaterThan(40000);

        String[] scopes = UriUtils.decode(params.getFirst("scope"), "UTF-8").split(" ");
        assertThat(Arrays.asList(scopes)).containsExactlyInAnyOrder("scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read", "uaa.user");

        validateToken("access_token", params.toSingleValueMap(), scopes, aud);
        validateToken("id_token", params.toSingleValueMap(), openid, new String[]{"cf"});
    }

    private void validateToken(String paramName, Map params, String[] scopes, String[] aud) {
        Map<String, Object> claims = UaaTokenUtils.getClaims((String) params.get(paramName), Map.class);

        assertThat(claims).containsEntry("jti", params.get("jti"))
                .containsEntry("client_id", "cf")
                .containsEntry("cid", "cf")
                .containsEntry("user_name", user.getUserName());
        assertThat(((List<String>) claims.get(ClaimConstants.SCOPE))).containsExactlyInAnyOrder(scopes);
        assertThat(((List<String>) claims.get(ClaimConstants.AUD))).containsExactlyInAnyOrder(aud);
    }

    @Test
    void passwordGrant() {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64("cf:".getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization", basicDigestHeaderValue);

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "cf");
        postBody.add("redirect_uri", "https://uaa.cloudfoundry.com/redirect/cf");
        postBody.add("response_type", "token id_token");
        postBody.add("grant_type", "password");
        postBody.add("username", user.getUserName());
        postBody.add("password", secret);

        ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Map.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);

        Map<String, Object> params = responseEntity.getBody();

        assertThat(params).containsKey("jti")
                .containsEntry("token_type", "bearer");
        assertThat((Integer) params.get("expires_in")).isGreaterThan(40000);

        String[] scopes = UriUtils.decode((String) params.get("scope"), "UTF-8").split(" ");
        assertThat(Arrays.asList(scopes)).containsExactlyInAnyOrder("scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read", "uaa.user");

        validateToken("access_token", params, scopes, aud);
        validateToken("id_token", params, openid, new String[]{"cf"});
    }

    @Test
    void openIdHybridFlowIdTokenAndCode() {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token", "code")), ".+access_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token", "code")), ".+access_token=.+code=.+");
    }

    @Test
    void openIdHybridFlowIdTokenAndTokenAndCode() {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token", "id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token", "id_token", "code")), ".+access_token=.+id_token=.+code=.+");
    }

    @Test
    void openIdHybridFlowIdTokenAndToken() {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("id_token", "code")), ".+id_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("id_token", "code")), ".+id_token=.+code=.+");
    }

    private void doOpenIdHybridFlowIdTokenAndCode(Set<String> responseTypes, String responseTypeMatcher) {

        BasicCookieStore cookies = new BasicCookieStore();

        StringBuilder responseType = new StringBuilder();
        Iterator<String> rTypes = responseTypes.iterator();
        while (rTypes.hasNext()) {
            String type = rTypes.next();
            responseType.append(type);
            if (rTypes.hasNext()) {
                responseType.append(" ");
            }
        }
        String state = new RandomValueStringGenerator().generate();
        String clientId = "app";
        String clientSecret = "appclientsecret";
        String redirectUri = "http://localhost:8080/app/";
        String uri = baseUrl +
                "/oauth/authorize?response_type={response_type}&" +
                "state={state}&client_id={client_id}&redirect_uri={redirect_uri}";

        ResponseEntity<Void> result = restOperations.exchange(
                uri,
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                Void.class,
                responseType,
                state,
                clientId,
                redirectUri
        );
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        IntegrationTestUtils.extractCookies(result, cookies);

        ResponseEntity<String> response = restOperations.exchange(
                location,
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                String.class);
        // should be directed to the login screen...
        assertThat(response.getBody()).contains("/login.do")
                .contains("username")
                .contains("password");
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());
        IntegrationTestUtils.extractCookies(response, cookies);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", user.getUserName());
        formData.add("password", secret);
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        // Should be redirected to the original URL, but now authenticated
        result = restOperations.exchange(baseUrl + "/login.do", HttpMethod.POST, new HttpEntity<>(formData, getHeaders(cookies)), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        cookies.clear();
        IntegrationTestUtils.extractCookies(result, cookies);

        location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        response = restOperations.exchange(
                location,
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                String.class);
        IntegrationTestUtils.extractCookies(response, cookies);

        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertThat(response.getBody()).contains("You can change your approval of permissions");

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = restOperations.exchange(baseUrl + "/oauth/authorize", HttpMethod.POST, new HttpEntity<>(formData, getHeaders(cookies)), Void.class);
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        } else {
            // Token cached so no need for second approval
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = UriUtils.decode(response.getHeaders().getLocation().toString(), "UTF-8");
        }
        assertThat(location).as("Wrong location: " + location).matches(redirectUri + responseTypeMatcher);

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        tokenHeaders.set("Authorization", basicDigestHeaderValue);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(formData, tokenHeaders), Map.class);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertThat(token.getClaims()).as("Wrong claims: " + token.getClaims()).contains("\"aud\"")
                .as("Wrong claims: " + token.getClaims()).contains("\"user_id\"");
    }

    private MultiValueMap<String, String> parseFragmentParams(UriComponents locationComponents) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        String[] tuples = locationComponents.getFragment().split("&");
        for (String tuple : tuples) {
            String[] parts = tuple.split("=");
            params.add(parts[0], parts[1]);
        }
        return params;
    }
}
