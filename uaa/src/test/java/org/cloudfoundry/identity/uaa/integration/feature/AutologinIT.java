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

import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class AutologinIT {

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

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    LinkedMultiValueMap<String, String> map = new LinkedMultiValueMap<>();


    @Before
    @After
    public void logout_and_clear_cookies() {
        map.add("username", testAccounts.getUserName());
        map.add("password", testAccounts.getPassword());
        try {
            webDriver.get(baseUrl + "/logout.do");
        }catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
        webDriver.get(appUrl+"/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    public void testAutologinFlow_FORM() throws Exception {
        testAutologinFlow(MediaType.APPLICATION_FORM_URLENCODED_VALUE, map);
    }

    @Test
    public void testAutologinFlow_JSON() throws Exception {
        testAutologinFlow(MediaType.APPLICATION_JSON_VALUE, map.toSingleValueMap());
    }
    public void testAutologinFlow(String contentType, Map body) {
        webDriver.get(baseUrl + "/logout.do");
        HttpHeaders headers = getAppBasicAuthHttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, contentType);



        ResponseEntity<Map> autologinResponseEntity = restOperations.exchange(baseUrl + "/autologin",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                Map.class);
        String autologinCode = (String) autologinResponseEntity.getBody().get("code");

        String authorizeUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
                .path("/oauth/authorize")
                .queryParam("redirect_uri", appUrl)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("client_id", "app")
                .queryParam("code", autologinCode)
                .build().toUriString();

        webDriver.get(authorizeUrl);

        webDriver.get(baseUrl);

        Assert.assertEquals(testAccounts.getUserName(), webDriver.findElement(By.cssSelector(".header .nav")).getText());
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver, IdentityZoneHolder.get());
    }

    @Test
    public void testSimpleAutologinFlow() throws Exception {
        HttpHeaders headers = getAppBasicAuthHttpHeaders();

        LinkedMultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", testAccounts.getUserName());
        requestBody.add("password", testAccounts.getPassword());

        //generate an autologin code with our credentials
        ResponseEntity<Map> autologinResponseEntity = restOperations.exchange(baseUrl + "/autologin",
                                                                              HttpMethod.POST,
                                                                              new HttpEntity<>(requestBody.toSingleValueMap(), headers),
                                                                              Map.class);
        String autologinCode = (String) autologinResponseEntity.getBody().get("code");

        //start the authorization flow - this will issue a login event
        //by using the autologin code
        String authorizeUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
            .path("/oauth/authorize")
            .queryParam("redirect_uri", appUrl)
            .queryParam("response_type", "code")
            .queryParam("client_id", "app")
            .queryParam("code", autologinCode)
            .build().toUriString();

        //rest template that does NOT follow redirects
        RestTemplate template = new RestTemplate(new DefaultIntegrationTestConfig.HttpClientFactory());
        headers.remove("Authorization");
        headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> authorizeResponse =
            template.exchange(authorizeUrl,
                              HttpMethod.GET,
                              new HttpEntity<>(new HashMap<String, String>(), headers),
                              String.class);


        //we are now logged in. retrieve the JSESSIONID
        List<String> cookies = authorizeResponse.getHeaders().get("Set-Cookie");
        int cookiesAdded = 0;
        headers = getAppBasicAuthHttpHeaders();
        for (String cookie : cookies) {
            if (cookie.startsWith("X-Uaa-Csrf=") || cookie.startsWith("JSESSIONID=")) {
                headers.add("Cookie", cookie);
                cookiesAdded++;
            }
        }
        assertEquals(2, cookiesAdded);

        //if we receive a 200, then we must approve our scopes
        if (HttpStatus.OK == authorizeResponse.getStatusCode()) {
            authorizeUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
                .path("/oauth/authorize")
                .queryParam("user_oauth_approval", "true")
                .queryParam(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(authorizeResponse.getBody()))
                .build().toUriString();
            authorizeResponse = template.exchange(authorizeUrl,
                                                  HttpMethod.POST,
                                                  new HttpEntity<>(new HashMap<String,String>(),headers),
                                                  String.class);
        }

        //approval is complete, we receive a token code back
        assertEquals(HttpStatus.FOUND, authorizeResponse.getStatusCode());
        List<String> location = authorizeResponse.getHeaders().get("Location");
        assertEquals(1, location.size());
        String newCode = location.get(0).substring(location.get(0).indexOf("code=") + 5);

        //request a token using our code
        String tokenUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
            .path("/oauth/token")
            .build().toUriString();

        MultiValueMap<String,String> tokenParams = new LinkedMultiValueMap<>();
        tokenParams.add("response_type", "token");
        tokenParams.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        tokenParams.add("code", newCode);
        tokenParams.add("redirect_uri", appUrl);
        headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);

        RequestEntity<MultiValueMap<String,String>> requestEntity = new RequestEntity<>(
            tokenParams,
            headers,
            HttpMethod.POST,
            new URI(tokenUrl)
        );
        ResponseEntity<Map> tokenResponse = template.exchange(requestEntity,Map.class);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());

        //here we must reset our state. we do that by following the logout flow.
        headers.clear();

        BasicCookieStore cookieStore = new BasicCookieStore();
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
                                                                 HttpMethod.GET,
                                                                 new HttpEntity<>(null, getHeaders(cookieStore)),
                                                                 String.class);

        setCookiesFromResponse(cookieStore, loginResponse);
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());
        requestBody.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginResponse = restOperations.exchange(baseUrl + "/login.do",
                                                HttpMethod.POST,
                                                new HttpEntity<>(requestBody, getHeaders(cookieStore)),
                                                String.class);
        cookies = loginResponse.getHeaders().get("Set-Cookie");
        assertThat(cookies, hasItem(startsWith("JSESSIONID")));
        assertThat(cookies, hasItem(startsWith("X-Uaa-Csrf")));
        if (IdentityZoneHolder.get().getConfig().isAccountChooserEnabled()) {
            assertThat(cookies, hasItem(startsWith("Saved-Account-")));
        }
        assertThat(cookies, hasItem(startsWith("Current-User")));
        cookieStore.clear();
        setCookiesFromResponse(cookieStore, loginResponse);
        headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> profilePage =
            restOperations.exchange(baseUrl + "/profile",
                                    HttpMethod.GET,
                                    new HttpEntity<>(null, getHeaders(cookieStore)), String.class);

        setCookiesFromResponse(cookieStore, profilePage);
        String revokeApprovalsUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
            .path("/profile")
            .build().toUriString();
        requestBody.clear();
        requestBody.add("clientId","app");
        requestBody.add("delete","");
        requestBody.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(profilePage.getBody()));
        ResponseEntity<Void> revokeResponse = template.exchange(revokeApprovalsUrl,
                                                                HttpMethod.POST,
                                                                new HttpEntity<>(requestBody, getHeaders(cookieStore)),
                                                                Void.class);
        assertEquals(HttpStatus.FOUND, revokeResponse.getStatusCode());
    }

    private void setCookiesFromResponse(BasicCookieStore cookieStore, ResponseEntity<String> loginResponse) {
        if (loginResponse.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : loginResponse.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookieStore.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }
    }

    @Test
    public void testFormEncodedAutologinRequest() {
        HttpHeaders headers = getAppBasicAuthHttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", testAccounts.getUserName());
        requestBody.add("password", testAccounts.getPassword());

        ResponseEntity<Map> autologinResponseEntity = restOperations.exchange(baseUrl + "/autologin",
                HttpMethod.POST,
                new HttpEntity<>(requestBody.toSingleValueMap(), headers),
                Map.class);

        String autologinCode = (String) autologinResponseEntity.getBody().get("code");
        assertEquals(10, autologinCode.length());
    }

    @Test
    public void testPasswordRequired() {
        HttpHeaders headers = getAppBasicAuthHttpHeaders();

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", testAccounts.getUserName());

        try {
            restOperations.exchange(baseUrl + "/autologin",
                    HttpMethod.POST,
                    new HttpEntity<>(requestBody, headers),
                    Map.class);
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void testClientAuthorization() {
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", testAccounts.getUserName());
        requestBody.put("password", testAccounts.getPassword());

        try {
            restOperations.exchange(baseUrl + "/autologin",
                    HttpMethod.POST,
                    new HttpEntity<>(requestBody),
                    Map.class);
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    @Test
    public void testClientIdMustBeConsistent() {
        webDriver.get(baseUrl + "/logout.do");

        HttpHeaders headers = getAppBasicAuthHttpHeaders();

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", testAccounts.getUserName());
        requestBody.put("password", testAccounts.getPassword());

        ResponseEntity<Map> autologinResponseEntity = restOperations.exchange(baseUrl + "/autologin",
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers),
                Map.class);
        String autologinCode = (String) autologinResponseEntity.getBody().get("code");

        String authorizeUrl = UriComponentsBuilder.fromHttpUrl(baseUrl)
                .path("/oauth/authorize")
                .queryParam("redirect_uri", appUrl)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("client_id", "stealer_of_codes")
                .queryParam("code", autologinCode)
                .build().toUriString();

        try {
            restOperations.exchange(authorizeUrl, HttpMethod.GET, null, Void.class);
        } catch (HttpClientErrorException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatusCode());
        }
    }

    private HttpHeaders getAppBasicAuthHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", testClient.getBasicAuthHeaderValue("app", "appclientsecret"));
        return headers;
    }
}
