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

import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
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
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.getHeaders;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class AutologinIT {

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

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

    LinkedMultiValueMap<String, String> map = new LinkedMultiValueMap<>();

    @BeforeEach
    @AfterEach
    void logout_and_clear_cookies() {
        map.add("username", testAccounts.getUserName());
        map.add("password", testAccounts.getPassword());
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void autologinFlowFORM() {
        testAutologinFlow(MediaType.APPLICATION_FORM_URLENCODED_VALUE, map);
    }

    @Test
    void autologinFlowJSON() {
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

        String authorizeUrl = UriComponentsBuilder.fromUriString(baseUrl)
                .path("/oauth/authorize")
                .queryParam("redirect_uri", "http://localhost:8080/app")
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("client_id", "app")
                .queryParam("code", autologinCode)
                .build().toUriString();

        webDriver.get(authorizeUrl);

        webDriver.get(baseUrl);

        assertThat(webDriver.findElement(By.cssSelector(".header .nav")).getText()).isEqualTo(testAccounts.getUserName());
        IntegrationTestUtils.validateAccountChooserCookie(baseUrl, webDriver, IdentityZoneHolder.get());
    }

    @Test
    void simpleAutologinFlow() throws Exception {
        HttpHeaders headers = getAppBasicAuthHttpHeaders();
        String password = testAccounts.getPassword();
        String userName = createNewUser(password);

        LinkedMultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", userName);
        requestBody.add("password", password);

        //generate an autologin code with our credentials
        ResponseEntity<Map> autologinResponseEntity = restOperations.exchange(baseUrl + "/autologin",
                HttpMethod.POST,
                new HttpEntity<>(requestBody.toSingleValueMap(), headers),
                Map.class);
        String autologinCode = (String) autologinResponseEntity.getBody().get("code");

        //start the authorization flow - this will issue a login event
        //by using the autologin code
        String authorizeUrl = UriComponentsBuilder.fromUriString(baseUrl)
                .path("/oauth/authorize")
                .queryParam("redirect_uri", "http://localhost:8080/app")
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

        //we are now logged in. check that we have the correct cookies set
        List<String> cookies = authorizeResponse.getHeaders().get("Set-Cookie");
        assertThat(cookies).as("Expected both JSESSIONID and X-Uaa-Csrf cookies to be set")
                .anySatisfy(s -> assertThat(s).startsWith("JSESSIONID="))
                .anySatisfy(s -> assertThat(s).startsWith("X-Uaa-Csrf="));

        headers = getAppBasicAuthHttpHeaders();
        for (String cookie : cookies) {
            if (cookie.startsWith("X-Uaa-Csrf=") || cookie.startsWith("JSESSIONID=")) {
                headers.add("Cookie", cookie);
            }
        }

        //if we receive a 200, then we must approve our scopes
        if (HttpStatus.OK == authorizeResponse.getStatusCode()) {
            authorizeUrl = UriComponentsBuilder.fromUriString(baseUrl)
                    .path("/oauth/authorize")
                    .queryParam("user_oauth_approval", "true")
                    .queryParam(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(authorizeResponse.getBody()))
                    .build().toUriString();
            authorizeResponse = template.exchange(authorizeUrl,
                    HttpMethod.POST,
                    new HttpEntity<>(new HashMap<String, String>(), headers),
                    String.class);
        }

        //approval is complete, we receive a token code back
        assertThat(authorizeResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        List<String> location = authorizeResponse.getHeaders().get("Location");
        assertThat(location).hasSize(1);
        String newCode = location.getFirst().substring(location.getFirst().indexOf("code=") + 5);

        //request a token using our code
        String tokenUrl = UriComponentsBuilder.fromUriString(baseUrl)
                .path("/oauth/token")
                .build().toUriString();

        MultiValueMap<String, String> tokenParams = new LinkedMultiValueMap<>();
        tokenParams.add("response_type", "token");
        tokenParams.add("grant_type", GRANT_TYPE_AUTHORIZATION_CODE);
        tokenParams.add("code", newCode);
        tokenParams.add("redirect_uri", "http://localhost:8080/app");
        headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(
                tokenParams,
                headers,
                HttpMethod.POST,
                new URI(tokenUrl)
        );
        ResponseEntity<Map> tokenResponse = template.exchange(requestEntity, Map.class);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        //here we must reset our state. we do that by following the logout flow.
        headers.clear();

        BasicCookieStore cookieStore = new BasicCookieStore();
        ResponseEntity<String> loginResponse = template.exchange(baseUrl + "/login",
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookieStore)),
                String.class);

        IntegrationTestUtils.extractCookies(loginResponse, cookieStore);
        String csrf = IntegrationTestUtils.extractCookieCsrf(loginResponse.getBody());
        requestBody.add(DEFAULT_CSRF_COOKIE_NAME, csrf);

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        loginResponse = restOperations.exchange(baseUrl + "/login.do",
                HttpMethod.POST,
                new HttpEntity<>(requestBody, getHeaders(cookieStore)),
                String.class);
        cookies = loginResponse.getHeaders().get("Set-Cookie");
        assertThat(cookies).anySatisfy(s -> assertThat(s).startsWith("JSESSIONID"))
                .anySatisfy(s -> assertThat(s).startsWith("X-Uaa-Csrf"));
        if (IdentityZoneHolder.get().getConfig().isAccountChooserEnabled()) {
            assertThat(cookies).anySatisfy(s -> assertThat(s).startsWith("Saved-Account-"));
        }
        assertThat(cookies).anySatisfy(s -> assertThat(s).startsWith("Current-User"));
        cookieStore.clear();
        IntegrationTestUtils.extractCookies(loginResponse, cookieStore);
        headers.add(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
        ResponseEntity<String> profilePage =
                restOperations.exchange(baseUrl + "/profile",
                        HttpMethod.GET,
                        new HttpEntity<>(null, getHeaders(cookieStore)), String.class);

        IntegrationTestUtils.extractCookies(profilePage, cookieStore);
        String revokeApprovalsUrl = UriComponentsBuilder.fromUriString(baseUrl)
                .path("/profile")
                .build().toUriString();
        requestBody.clear();
        requestBody.add("clientId", "app");
        requestBody.add("delete", "");
        requestBody.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(profilePage.getBody()));
        ResponseEntity<Void> revokeResponse = template.exchange(revokeApprovalsUrl,
                HttpMethod.POST,
                new HttpEntity<>(requestBody, getHeaders(cookieStore)),
                Void.class);
        assertThat(revokeResponse.getStatusCode()).isEqualTo(HttpStatus.FOUND);
    }

    @Test
    void formEncodedAutologinRequest() {
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
        assertThat(autologinCode).hasSize(32);
    }

    @Test
    void passwordRequired() {
        HttpHeaders headers = getAppBasicAuthHttpHeaders();

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", testAccounts.getUserName());

        try {
            restOperations.exchange(baseUrl + "/autologin",
                    HttpMethod.POST,
                    new HttpEntity<>(requestBody, headers),
                    Map.class);
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Test
    void clientAuthorization() {
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("username", testAccounts.getUserName());
        requestBody.put("password", testAccounts.getPassword());

        try {
            restOperations.exchange(baseUrl + "/autologin",
                    HttpMethod.POST,
                    new HttpEntity<>(requestBody),
                    Map.class);
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    @Test
    void clientIdMustBeConsistent() {
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

        String authorizeUrl = UriComponentsBuilder.fromUriString(baseUrl)
                .path("/oauth/authorize")
                .queryParam("redirect_uri", "http://localhost:8080/app")
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("client_id", "stealer_of_codes")
                .queryParam("code", autologinCode)
                .build().toUriString();

        try {
            restOperations.exchange(authorizeUrl, HttpMethod.GET, null, Void.class);
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }

    private HttpHeaders getAppBasicAuthHttpHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", testClient.getBasicAuthHeaderValue("app", "appclientsecret"));
        return headers;
    }

    private String createNewUser(String secretPassword) {
        int randomInt = new SecureRandom().nextInt();
        String adminAccessToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials", "clients.admin");
        String scimClientId = "app" + randomInt;
        testClient.createScimClient(adminAccessToken, scimClientId);
        String scimAccessToken = testClient.getOAuthAccessToken(scimClientId, "scimsecret", "client_credentials", "scim.read scim.write password.write");
        String userEmail = "user" + randomInt + "@example.com";
        testClient.createUser(scimAccessToken, userEmail, userEmail, secretPassword, true);
        return userEmail;
    }
}
