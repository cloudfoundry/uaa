/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
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
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class OpenIdTokenGrantsIT {



    @Autowired
    TestAccounts testAccounts;

    @Autowired @Rule
    public IntegrationTestRule integrationTestRule;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String loginUrl;

    @Value("${integration.test.uaa_url}")
    String uaaUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    private RestTemplate client;

    private ScimUser user;

    @Before
    public void setUp() throws Exception {
        ((RestTemplate)restOperations).setRequestFactory(new IntegrationTestUtils.StatelessRequestFactory());
        ClientCredentialsResourceDetails clientCredentials =
            getClientCredentialsResource(new String[] {"scim.write"}, testAccounts.getAdminClientId(), testAccounts.getAdminClientSecret());
        client = IntegrationTestUtils.getClientCredentialsTempate(clientCredentials);
        user = createUser(new RandomValueStringGenerator().generate(), "openiduser", "openidlast", "test@openid,com",true);
    }


    private ClientCredentialsResourceDetails getClientCredentialsResource(String[] scope, String clientId,
                                                                         String clientSecret) {
        return IntegrationTestUtils.getClientCredentialsResource(uaaUrl,scope,clientId,clientSecret);
    }

    private ScimUser createUser(String username, String firstName, String lastName,
                                                String email, boolean verified) {
        return IntegrationTestUtils.createUser(client, uaaUrl, username, firstName, lastName, email, verified);
    }

    @Test
    public void testImplicitGrant() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "cf");
        postBody.add("redirect_uri", "https://uaa.cloudfoundry.com/redirect/cf");
        postBody.add("response_type", "token id_token");
        postBody.add("source", "credentials");
        postBody.add("username", user.getUserName());
        postBody.add("password", "secret");

        ResponseEntity<Void> responseEntity = restOperations.exchange(loginUrl + "/oauth/authorize",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

        Assert.assertEquals(HttpStatus.FOUND, responseEntity.getStatusCode());

        UriComponents locationComponents = UriComponentsBuilder.fromUri(responseEntity.getHeaders().getLocation()).build();
        Assert.assertEquals("uaa.cloudfoundry.com", locationComponents.getHost());
        Assert.assertEquals("/redirect/cf", locationComponents.getPath());

        MultiValueMap<String, String> params = parseFragmentParams(locationComponents);

        Assert.assertThat(params.get("jti"), not(empty()));
        Assert.assertEquals("bearer", params.getFirst("token_type"));
        Assert.assertThat(Integer.parseInt(params.getFirst("expires_in")), Matchers.greaterThan(40000));

        String[] scopes = UriUtils.decode(params.getFirst("scope"), "UTF-8").split(" ");
        Assert.assertThat(Arrays.asList(scopes), containsInAnyOrder(
                "scim.userids",
                "password.write",
                "cloud_controller.write",
                "openid",
                "cloud_controller.read"
        ));

        validateToken("access_token", params.toSingleValueMap(), scopes);
        validateToken("id_token", params.toSingleValueMap(), scopes);
    }

    private void validateToken(String paramName, Map params, String[] scopes) throws java.io.IOException {
        Jwt access_token = JwtHelper.decode((String)params.get(paramName));

        Map<String, Object> claims = JsonUtils.readValue(access_token.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        Assert.assertThat((String) claims.get("jti"), is(params.get("jti")));
        Assert.assertThat((String) claims.get("client_id"), is("cf"));
        Assert.assertThat((String) claims.get("cid"), is("cf"));
        Assert.assertThat((String) claims.get("user_name"), is(user.getUserName()));

        Assert.assertThat(((List<String>) claims.get("scope")), containsInAnyOrder(scopes));

        Assert.assertThat(((List<String>) claims.get("aud")), containsInAnyOrder(
                "scim", "openid", "cloud_controller", "password", "cf"));
    }

    @Test
    public void testPasswordGrant() throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("cf:").getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.set("Authorization", basicDigestHeaderValue);

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "cf");
        postBody.add("redirect_uri", "https://uaa.cloudfoundry.com/redirect/cf");
        postBody.add("response_type", "token id_token");
        postBody.add("grant_type", "password");
        postBody.add("username", user.getUserName());
        postBody.add("password", "secret");

        ResponseEntity<Map> responseEntity = restOperations.exchange(loginUrl + "/oauth/token",
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

        validateToken("access_token", params, scopes);
        validateToken("id_token", params, scopes);
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndCode() throws Exception {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndTokenAndCode() throws Exception {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndToken() throws Exception {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
    }

    private void doOpenIdHybridFlowIdTokenAndCode(Set<String> responseTypes, String responseTypeMatcher) throws Exception {

        HttpHeaders headers = new HttpHeaders();
        // TODO: should be able to handle just TEXT_HTML
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

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
        String redirectUri = "http://anywhere.com";
        String uri = loginUrl + "/oauth/authorize?response_type={response_type}&"+
            "state={state}&client_id={client_id}&redirect_uri={redirect_uri}";

        ResponseEntity<Void> result = restOperations.exchange(
            uri,
            HttpMethod.GET,
            new HttpEntity<>(null, headers),
            Void.class,
            responseType,
            state,
            clientId,
            redirectUri
        );
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");

        if (result.getHeaders().containsKey("Set-Cookie")) {
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        ResponseEntity<String> response = restOperations.exchange(
            location,
            HttpMethod.GET,
            new HttpEntity<>(null, headers),
            String.class);
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", user.getUserName());
        formData.add("password", "secret");

        // Should be redirected to the original URL, but now authenticated
        result = restOperations.exchange(loginUrl + "/login.do", HttpMethod.POST, new HttpEntity<>(formData, headers), Void.class);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        if (result.getHeaders().containsKey("Set-Cookie")) {
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        response = restOperations.exchange(
            location,
            HttpMethod.GET,
            new HttpEntity<>(null, headers),
            String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("You can change your approval of permissions"));

            formData.clear();
            formData.add("user_oauth_approval", "true");
            result = restOperations.exchange(loginUrl + "/oauth/authorize", HttpMethod.POST, new HttpEntity<>(formData, headers), Void.class);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = UriUtils.decode(response.getHeaders().getLocation().toString(), "UTF-8");
        }
        assertTrue("Wrong location: " + location,
            location.matches(redirectUri + responseTypeMatcher.toString()));

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("redirect_uri", redirectUri);
        formData.add("grant_type", "authorization_code");
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        tokenHeaders.set("Authorization", basicDigestHeaderValue);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = restOperations.exchange(loginUrl+"/oauth/token", HttpMethod.POST, new HttpEntity<>(formData, tokenHeaders), Map.class);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"aud\""));
        assertTrue("Wrong claims: " + token.getClaims(), token.getClaims().contains("\"user_id\""));
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
