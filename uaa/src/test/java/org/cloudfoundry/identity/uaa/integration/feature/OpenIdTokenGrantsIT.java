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
package org.cloudfoundry.identity.uaa.integration.feature;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.jwt.Jwt;
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

import java.util.*;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

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
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    private RestTemplate client;

    private ScimUser user;
    private String secret = "secr3T";

    private String[] aud = {"scim", "openid", "cloud_controller", "password", "cf", "uaa"};
    private String[] openid = new String[] {"openid"};

    @Before
    public void setUp() {
        ((RestTemplate)restOperations).setRequestFactory(new IntegrationTestUtils.StatelessRequestFactory());
        ClientCredentialsResourceDetails clientCredentials =
            getClientCredentialsResource(new String[] {"scim.write"}, testAccounts.getAdminClientId(), testAccounts.getAdminClientSecret());
        client = IntegrationTestUtils.getClientCredentialsTemplate(clientCredentials);
        user = createUser(new RandomValueStringGenerator().generate(), "openiduser", "openidlast", "test@openid,com",true);
    }

    @Before
    @After
    public void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl+"/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    private ClientCredentialsResourceDetails getClientCredentialsResource(String[] scope, String clientId,
                                                                         String clientSecret) {
        return IntegrationTestUtils.getClientCredentialsResource(baseUrl,scope,clientId,clientSecret);
    }

    private ScimUser createUser(String username, String firstName, String lastName,
                                                String email, boolean verified) {
        return IntegrationTestUtils.createUser(client, baseUrl, username, firstName, lastName, email, verified);
    }

    @Test
    public void testImplicitGrant() {
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

        assertEquals(HttpStatus.FOUND, responseEntity.getStatusCode());

        UriComponents locationComponents = UriComponentsBuilder.fromUri(responseEntity.getHeaders().getLocation()).build();
        assertEquals("localhost", locationComponents.getHost());
        assertEquals("/redirect/cf", locationComponents.getPath());

        MultiValueMap<String, String> params = parseFragmentParams(locationComponents);

        assertThat(params.get("jti"), not(empty()));
        assertEquals("bearer", params.getFirst("token_type"));
        assertThat(Integer.parseInt(params.getFirst("expires_in")), Matchers.greaterThan(40000));

        String[] scopes = UriUtils.decode(params.getFirst("scope"), "UTF-8").split(" ");
        assertThat(Arrays.asList(scopes), containsInAnyOrder(
            "scim.userids",
            "password.write",
            "cloud_controller.write",
            "openid",
            "cloud_controller.read",
            "uaa.user"
        ));

        validateToken("access_token", params.toSingleValueMap(), scopes, aud);
        validateToken("id_token", params.toSingleValueMap(), openid, new String[] {"cf"});
    }

    private void validateToken(String paramName, Map params, String[] scopes, String[] aud) {
        Jwt access_token = JwtHelper.decode((String)params.get(paramName));

        Map<String, Object> claims = JsonUtils.readValue(access_token.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        assertThat(claims.get("jti"), is(params.get("jti")));
        assertThat(claims.get("client_id"), is("cf"));
        assertThat(claims.get("cid"), is("cf"));
        assertThat(claims.get("user_name"), is(user.getUserName()));
        assertThat(((List<String>) claims.get(ClaimConstants.SCOPE)), containsInAnyOrder(scopes));
        assertThat(((List<String>) claims.get(ClaimConstants.AUD)), containsInAnyOrder(aud));
    }

    @Test
    public void testPasswordGrant() {
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("cf:").getBytes()));

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

        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());

        Map<String, Object> params = responseEntity.getBody();

        assertNotNull(params.get("jti"));
        assertEquals("bearer", params.get("token_type"));
        assertThat((Integer)params.get("expires_in"), Matchers.greaterThan(40000));

        String[] scopes = UriUtils.decode((String)params.get("scope"), "UTF-8").split(" ");
        assertThat(Arrays.asList(scopes), containsInAnyOrder(
            "scim.userids",
            "password.write",
            "cloud_controller.write",
            "openid",
            "cloud_controller.read",
            "uaa.user"
        ));

        validateToken("access_token", params, scopes, aud);
        validateToken("id_token", params, openid, new String[] {"cf"});
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndCode() {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","code")), ".+access_token=.+code=.+");
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndTokenAndCode() {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("token","id_token", "code")), ".+access_token=.+id_token=.+code=.+");
    }

    @Test
    public void testOpenIdHybridFlowIdTokenAndToken() {
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
        doOpenIdHybridFlowIdTokenAndCode(new HashSet<>(Arrays.asList("id_token","code")), ".+id_token=.+code=.+");
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
                     "/oauth/authorize?response_type={response_type}&"+
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
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }

        ResponseEntity<String> response = restOperations.exchange(
            location,
            HttpMethod.GET,
            new HttpEntity<>(null, getHeaders(cookies)),
            String.class);
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));
        String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("username", user.getUserName());
        formData.add("password", secret);
        formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);

        // Should be redirected to the original URL, but now authenticated
        result = restOperations.exchange(baseUrl + "/login.do", HttpMethod.POST, new HttpEntity<>(formData, getHeaders(cookies)), Void.class);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        cookies.clear();
        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }


        location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        response = restOperations.exchange(
            location,
            HttpMethod.GET,
            new HttpEntity<>(null, getHeaders(cookies)),
            String.class);
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("You can change your approval of permissions"));

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = restOperations.exchange(baseUrl + "/oauth/authorize", HttpMethod.POST, new HttpEntity<>(formData, getHeaders(cookies)), Void.class);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = UriUtils.decode(result.getHeaders().getLocation().toString(), "UTF-8");
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = UriUtils.decode(response.getHeaders().getLocation().toString(), "UTF-8");
        }
        assertTrue("Wrong location: " + location,
            location.matches(redirectUri + responseTypeMatcher));

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
        ResponseEntity<Map> tokenResponse = restOperations.exchange(baseUrl+"/oauth/token", HttpMethod.POST, new HttpEntity<>(formData, tokenHeaders), Map.class);
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
