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
package org.cloudfoundry.identity.uaa.integration;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.extractCookieCsrf;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
class OpenIdTokenAuthorizationWithApprovalIntegrationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountExtension);

    private RestTemplate client;

    private RestTemplate loginClient;

    private ScimUser user;

    @BeforeEach
    void createRestTemplate() {

        ClientCredentialsResourceDetails clientCredentials =
                getClientCredentialsResource(new String[]{"oauth.login"}, "login", "loginsecret");
        loginClient = new OAuth2RestTemplate(clientCredentials);
        loginClient.setRequestFactory(new StatelessRequestFactory());
        loginClient.setErrorHandler(new OAuth2ErrorHandler(clientCredentials) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pass through
            }
        });

        client = (RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // pas through
            }
        });
        user = createUser(new RandomValueStringGenerator().generate(), "openiduser", "openidlast", "test@openid,com", true).getBody();
    }

    @Test
    void openIdTokenUsingLoginClientOauthTokenEndpoint() {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "app");
        postBody.add("client_secret", "appclientsecret");
        postBody.add("redirect_uri", "https://uaa.cloudfoundry.com/redirect/cf");
        postBody.add("response_type", "token id_token");
        postBody.add("grant_type", "password");
        postBody.add("source", "login");
        postBody.add("user_id", user.getId());
        postBody.add("add_new", "false");

        ResponseEntity<Map> responseEntity = loginClient.exchange(serverRunning.getBaseUrl() + "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Map.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);

        Map<String, Object> params = responseEntity.getBody();

        assertThat(params).containsKey("jti")
                .containsEntry("token_type", "bearer");
        assertThat((Integer) params.get("expires_in")).isGreaterThan(40000);

        String[] scopes = UriUtils.decode((String) params.get("scope"), "UTF-8").split(" ");
        assertThat(Arrays.asList(scopes)).containsExactlyInAnyOrder("scim.userids", "password.write", "cloud_controller.write", "openid", "cloud_controller.read");
    }

    @Test
    void openIdHybridFlowIdTokenAndCode() {
        //non approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token", "code")), ".+access_token=.+code=.+");
        //approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token", "code")), ".+access_token=.+code=.+");
        //approved using login client
        doOpenIdHybridFlowForLoginClient(new HashSet<>(Arrays.asList("token", "code")), ".+access_token=.+code=.+");
    }

    @Test
    void openIdHybridFlowIdTokenAndTokenAndCode() {
        //non approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token", "id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        //approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token", "id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        //approved using login client
        doOpenIdHybridFlowForLoginClient(new HashSet<>(Arrays.asList("token", "id_token", "code")), ".+access_token=.+id_token=.+code=.+");
    }

    @Test
    void openIdHybridFlowIdTokenAndToken() {
        //non approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("id_token", "code")), ".+id_token=.+code=.+");
        //approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("id_token", "code")), ".+id_token=.+code=.+");
        //approved using login client
        doOpenIdHybridFlowForLoginClient(new HashSet<>(Arrays.asList("id_token", "code")), ".+id_token=.+code=.+");
    }

    @Test
    void openIdHybridFlowZoneDoesNotExist() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

        String responseType = "id_token code";
        String state = new RandomValueStringGenerator().generate();
        String clientId = resource.getClientId();
        String redirectUri = resource.getPreEstablishedRedirectUri();
        String uri = serverRunning.getUrl("/oauth/authorize?response_type={response_type}&" +
                "state={state}&client_id={client_id}&redirect_uri={redirect_uri}").replace("localhost", "testzonedoesnotexist.localhost");
        RestTemplate restTemplate = serverRunning.createRestTemplate();

        ResponseEntity<Void> result = restTemplate.exchange(uri,
                HttpMethod.GET,
                new HttpEntity<Void>(null, new HttpHeaders()),
                Void.class,
                responseType,
                state,
                clientId,
                redirectUri);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void openIdHybridFlowZoneInactive() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");

        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

        String responseType = "id_token code";
        String state = new RandomValueStringGenerator().generate();
        String clientId = resource.getClientId();
        String redirectUri = resource.getPreEstablishedRedirectUri();
        String uri = serverRunning.getUrl("/oauth/authorize?response_type={response_type}&" +
                "state={state}&client_id={client_id}&redirect_uri={redirect_uri}").replace("localhost", "testzoneinactive.localhost");
        RestTemplate restTemplate = serverRunning.createRestTemplate();

        ResponseEntity<Void> result = restTemplate.exchange(uri,
                HttpMethod.GET,
                new HttpEntity<Void>(null, new HttpHeaders()),
                Void.class,
                responseType,
                state,
                clientId,
                redirectUri);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    private String doOpenIdHybridFlowIdTokenAndReturnCode(Set<String> responseTypes, String responseTypeMatcher) {
        BasicCookieStore cookies = new BasicCookieStore();
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

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
        String clientId = resource.getClientId();
        String redirectUri = resource.getPreEstablishedRedirectUri();
        String clientSecret = resource.getClientSecret();
        String uri = serverRunning.getUrl("/oauth/authorize?response_type={response_type}&" +
                "state={state}&client_id={client_id}&redirect_uri={redirect_uri}");
        RestTemplate restTemplate = serverRunning.createRestTemplate();

        ResponseEntity<Void> result = restTemplate.exchange(uri,
                HttpMethod.GET,
                new HttpEntity<Void>(null, getHeaders(cookies)),
                Void.class,
                responseType,
                state,
                clientId,
                redirectUri);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        IntegrationTestUtils.extractCookies(result, cookies);


        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));
        IntegrationTestUtils.extractCookies(response, cookies);

        // should be directed to the login screen...
        assertThat(response.getBody()).contains("/login.do")
                .contains("username")
                .contains("password");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", user.getUserName());
        formData.add("password", "s3Cret");
        formData.add(DEFAULT_CSRF_COOKIE_NAME, extractCookieCsrf(response.getBody()));

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        cookies.clear();
        IntegrationTestUtils.extractCookies(result, cookies);

        location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        response = restTemplate.exchange(location,
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                String.class);
        IntegrationTestUtils.extractCookies(response, cookies);

        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertThat(response.getBody()).contains("Application Authorization</h1>");

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, extractCookieCsrf(response.getBody()));
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        } else {
            // Token cached so no need for second approval
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            location = UriUtils.decode(response.getHeaders().getLocation().toString(), "UTF-8");
        }
        assertThat(location).as("Wrong location: " + location).matches(resource.getPreEstablishedRedirectUri() + responseTypeMatcher);

        String code = location.split("code=")[1].split("&")[0];
        exchangeCodeForToken(clientId, redirectUri, clientSecret, code, formData);
        return code;
    }

    private void doOpenIdHybridFlowForLoginClient(Set<String> responseTypes, String responseTypeMatcher) {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON, MediaType.ALL));

        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

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
        String clientId = resource.getClientId();
        String redirectUri = resource.getPreEstablishedRedirectUri();
        String clientSecret = resource.getClientSecret();
        String uri = serverRunning.getUrl("/oauth/authorize?response_type={response_type}&" +
                "state={state}&client_id={client_id}&client_secret={clientSecret}&redirect_uri={redirect_uri}&source=login&user_id={userId}&add_new=false");

        HttpEntity<Void> request = new HttpEntity<>(null, headers);
        ResponseEntity<Map> result = loginClient.exchange(
                serverRunning.getUrl(uri),
                HttpMethod.POST,
                request,
                Map.class,
                responseType,
                state,
                clientId,
                clientSecret,
                redirectUri,
                user.getId());

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        assertThat(location).as("Wrong location: " + location).matches(resource.getPreEstablishedRedirectUri() + responseTypeMatcher);
    }

    private void exchangeCodeForToken(String clientId, String redirectUri, String clientSecret, String value, MultiValueMap<String, String> formData) {
        formData.clear();
        formData.add("client_id", clientId);
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        formData.add("code", value);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",
                testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertThat(token.getClaims()).as("Wrong claims: " + token.getClaims()).contains("\"aud\"")
                .as("Wrong claims: " + token.getClaims()).contains("\"user_id\"");
    }

    private ResponseEntity<ScimUser> createUser(String username, String firstName, String lastName,
                                                String email, boolean verified) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);
        user.setActive(true);
        user.setPassword("s3Cret");

        String userEndpoint = "/Users";
        return client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
    }

    private ClientCredentialsResourceDetails getClientCredentialsResource(String[] scope, String clientId,
                                                                          String clientSecret) {
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setId(clientId);
        if (scope != null) {
            resource.setScope(Arrays.asList(scope));
        }
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(serverRunning.getBaseUrl() + "/oauth/token");
        return resource;
    }

    private static class StatelessRequestFactory extends HttpComponentsClientHttpRequestFactory {
        @Override
        public HttpClient getHttpClient() {
            return HttpClientBuilder.create()
                    .useSystemProperties()
                    .disableRedirectHandling()
                    .disableCookieManagement()
                    .build();
        }
    }
}
