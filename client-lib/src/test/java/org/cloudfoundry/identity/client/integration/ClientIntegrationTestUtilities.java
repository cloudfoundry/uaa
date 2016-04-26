/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.client.integration;

import org.cloudfoundry.identity.client.UaaContextFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.client.UaaContextFactory.getNoValidatingClientHttpRequestFactory;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML;

public class ClientIntegrationTestUtilities {
    public static final String DEFAULT_CSRF_COOKIE_NAME = "X-Uaa-Csrf";

    public static String UAA_URI = "http://localhost:8080/uaa";

    public static RandomValueStringGenerator GENERATOR = new RandomValueStringGenerator();

    public static String extractCookieCsrf(String body) {
        String pattern = "\\<input type=\\\"hidden\\\" name=\\\""+DEFAULT_CSRF_COOKIE_NAME+"\\\" value=\\\"(.*?)\\\"";
        Pattern linkPattern = Pattern.compile(pattern);
        Matcher matcher = linkPattern.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public static String getPasscode(String baseUrl, HttpHeaders headers) {
        headers.setAccept(Arrays.asList(APPLICATION_JSON));
        RestTemplate template = new RestTemplate();
        ResponseEntity<String> passcode = template.exchange(baseUrl+"/passcode", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        return passcode.getBody().replace('"',' ').trim();
    }

    public static String getAuthorizationCode(String authorizeUrl, String clientId, String redirectUri, HttpHeaders headers) {
        headers.setAccept(Arrays.asList(TEXT_HTML));
        RestTemplate template = new RestTemplate();
        template.setRequestFactory(UaaContextFactory.getNoValidatingClientHttpRequestFactory(false));
        String url = String.format(authorizeUrl+"?scope=openid&client_id=%s&response_type=code&redirect_uri=%s&state=%s",
                                   clientId,
                                   redirectUri,
                                   new RandomValueStringGenerator().generate());
        ResponseEntity<Void> redirect = template.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), Void.class);
        assertEquals(HttpStatus.FOUND, redirect.getStatusCode());
        String location = redirect.getHeaders().get("Location").get(0);
        return extractCodeFromLocation(location);

    }

    public static String extractCodeFromLocation(String location) {
        return location.split("code=")[1].split("&")[0];
    }


    public static HttpHeaders performFormLogin(String baseUrl, String username, String password) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(TEXT_HTML));
        RestTemplate template = new RestTemplate();
        template.setRequestFactory(getNoValidatingClientHttpRequestFactory());
        ResponseEntity<String> loginPage = template.exchange(baseUrl+"/login", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        String csrfValue = extractCookieCsrf(loginPage.getBody());
        HttpHeaders combined = extractAndSetCookies(loginPage);

        assertTrue(loginPage.getBody().contains("/login.do"));
        assertTrue(loginPage.getBody().contains("username"));
        assertTrue(loginPage.getBody().contains("password"));

        MultiValueMap<String,String> formData = new LinkedMultiValueMap<>();
        formData.add("username", username);
        formData.add("password", password);
        formData.add(DEFAULT_CSRF_COOKIE_NAME, csrfValue);
        headers.setContentType(APPLICATION_FORM_URLENCODED);
        // Should be redirected to the original URL, but now authenticated
        ResponseEntity<String> loggedInPage = template.exchange(baseUrl+"/login.do",
                                                                POST,
                                                                new HttpEntity<>(formData, headers),
                                                                String.class);

        assertEquals(HttpStatus.FOUND, loggedInPage.getStatusCode());
        HttpHeaders newHeaders = extractAndSetCookies(loggedInPage);
        for (String c : newHeaders.get("Cookie")) {
            combined.add("Cookie", c);
        }
        return combined;
    }

    protected static HttpHeaders extractAndSetCookies(ResponseEntity<String> response) {
        HttpHeaders result = new HttpHeaders();
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                if (StringUtils.hasText(cookie)) {
                    result.add("Cookie", cookie);
                }
            }
        }
        return result;
    }

    protected static String extractAndSetCookies(ResponseEntity<String> response, HttpHeaders headers, String findCookie) {
        String result = null;
        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                if (StringUtils.hasText(cookie)) {
                    headers.add("Cookie", cookie);
                    if (cookie.toLowerCase().contains(findCookie.toLowerCase())) {
                        result = cookie;
                    }
                }
            }
        }
        return result;
    }
}
