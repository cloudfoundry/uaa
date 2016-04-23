/*******************************************************************************
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

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class OpenIdTokenAuthorizationWithApprovalIntegrationTests {

    private final String userEndpoint = "/Users";

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private RestTemplate client;

    private RestTemplate loginClient;

    private ScimUser user;

    @Before
    public void createRestTemplate() throws Exception {

        ClientCredentialsResourceDetails clientCredentials =
            getClientCredentialsResource(new String[] {"oauth.login"}, "login", "loginsecret");
        loginClient = new OAuth2RestTemplate(clientCredentials);
        loginClient.setRequestFactory(new StatelessRequestFactory());
        loginClient.setErrorHandler(new OAuth2ErrorHandler(clientCredentials) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });

        Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));

        client = (RestTemplate)serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });
        user = createUser(new RandomValueStringGenerator().generate(), "openiduser", "openidlast", "test@openid,com",true).getBody();
    }

    @Test
    public void testOpenIdTokenUsingLoginClientOauthTokenEndpoint() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

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

        Assert.assertEquals(HttpStatus.OK, responseEntity.getStatusCode());

        Map<String, Object> params = responseEntity.getBody();

        Assert.assertTrue(params.get("jti") != null);
        Assert.assertEquals("bearer", params.get("token_type"));
        Assert.assertThat((Integer)params.get("expires_in"), Matchers.greaterThan(40000));

        String[] scopes = UriUtils.decode((String)params.get("scope"), "UTF-8").split(" ");
        Assert.assertThat(Arrays.asList(scopes), containsInAnyOrder(
            "scim.userids",
            "password.write",
            "cloud_controller.write",
            "openid",
            "cloud_controller.read"
        ));
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndCode() throws Exception {
        //non approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
        //approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
        //approved using login client
        doOpenIdHybridFlowForLoginClient(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndTokenAndCode() throws Exception {
        //non approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        //approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        //approved using login client
        doOpenIdHybridFlowForLoginClient(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndToken() throws Exception {
        //non approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
        //approved
        doOpenIdHybridFlowIdTokenAndReturnCode(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
        //approved using login client
        doOpenIdHybridFlowForLoginClient(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
    }

    private String doOpenIdHybridFlowIdTokenAndReturnCode(Set<String> responseTypes, String responseTypeMatcher) throws Exception {

        HttpHeaders headers = new HttpHeaders();
        // TODO: should be able to handle just TEXT_HTML
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

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
        String uri = serverRunning.getUrl("/oauth/authorize?response_type={response_type}&"+
            "state={state}&client_id={client_id}&redirect_uri={redirect_uri}");
        headers.remove("Authorization");
        RestTemplate restTemplate = serverRunning.createRestTemplate();

        ResponseEntity<Void> result = restTemplate.exchange(uri,
            HttpMethod.GET,
            new HttpEntity<Void>(null, headers),
            Void.class,
            responseType,
            state,
            clientId,
            redirectUri);

        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");

        if (result.getHeaders().containsKey("Set-Cookie")) {
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        ResponseEntity<String> response = serverRunning.getForString(location, headers);
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("username", user.getUserName());
        formData.add("password", "s3Cret");
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", headers, formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        headers.remove("Cookie");
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }

        location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        //response = serverRunning.getForString(location, headers);
        response = restTemplate.exchange(location,
            HttpMethod.GET,
            new HttpEntity<>(null,headers),
            String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("Application Authorization</h1>"));

            formData.clear();
            formData.add("user_oauth_approval", "true");
            result = serverRunning.postForResponse("/oauth/authorize", headers, formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = UriUtils.decode(response.getHeaders().getLocation().toString(), "UTF-8");
        }
        assertTrue("Wrong location: " + location,
            location.matches(resource.getPreEstablishedRedirectUri() + responseTypeMatcher.toString()));

        String code = location.split("code=")[1].split("&")[0];
        exchangeCodeForToken(clientId, redirectUri, clientSecret, code, formData);
        return code;
    }

    private void doOpenIdHybridFlowForLoginClient(Set<String> responseTypes, String responseTypeMatcher) throws Exception {

        HttpHeaders headers = new HttpHeaders();
        // TODO: should be able to handle just TEXT_HTML
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
        String uri = serverRunning.getUrl("/oauth/authorize?response_type={response_type}&"+
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

        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        assertTrue("Wrong location: " + location,
            location.matches(resource.getPreEstablishedRedirectUri() + responseTypeMatcher.toString()));


    }

    private void exchangeCodeForToken(String clientId, String redirectUri, String clientSecret, String value, MultiValueMap<String, String> formData) {
        formData.clear();
        formData.add("client_id", clientId);
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", "authorization_code");
        formData.add("code", value);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",
            testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"aud\""));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"user_id\""));
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
        resource.setAccessTokenUri(serverRunning.getBaseUrl()+"/oauth/token");
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
