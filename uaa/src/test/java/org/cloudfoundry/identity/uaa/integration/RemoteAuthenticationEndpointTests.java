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

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;

/**
 * @author Luke Taylor
 */
class RemoteAuthenticationEndpointTests {
    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Test
    void remoteAuthenticationSucceedsWithCorrectCredentials() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = authenticate(testAccounts.getUserName(), testAccounts.getPassword(), null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("username", testAccounts.getUserName())
                .containsEntry("email", testAccounts.getEmail());
    }

    @Test
    void remoteAuthenticationSucceedsAndCreatesUser() {
        String username = new RandomValueStringGenerator().generate();
        String origin = OriginKeys.LOGIN_SERVER;
        Map<String, Object> info = new HashMap<>();
        info.put("source", "login");
        info.put("add_new", "true");
        info.put(OriginKeys.ORIGIN, origin);
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = authenticate(username, null, info);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("username", username);
        validateOrigin(username, null, origin, info);
    }

    @Test
    void remoteAuthenticationFailsWithIncorrectCredentials() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = authenticate(testAccounts.getUserName(), "wrong", null);
        assertThat(response.getStatusCode()).isNotSameAs(HttpStatus.OK);
        assertThat(response.getBody()).doesNotContainEntry("username", testAccounts.getUserName());
    }

    @Test
    void validateLdapOrKeystoneOrigin() throws Exception {
        String profiles = System.getProperty("spring.profiles.active");
        if (profiles != null && profiles.contains(LDAP)) {
            validateOrigin("marissa3", "ldap3", LDAP, null);
        } else if (profiles != null && profiles.contains("keystone")) {
            validateOrigin("marissa2", "keystone", OriginKeys.KEYSTONE, null);
        } else {
            validateOrigin(testAccounts.getUserName(), testAccounts.getPassword(), OriginKeys.UAA, null);
        }
    }

    public void validateOrigin(String username, String password, String origin, Map<String, Object> info) {
        ResponseEntity<Map> authResp = authenticate(username, password, info);
        assertThat(authResp.getStatusCode()).isEqualTo(HttpStatus.OK);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + getScimReadBearerToken());
        ResponseEntity<Map> response = serverRunning.getForObject("/Users" + "?filter=userName eq \"" + username + "\"&attributes=id,userName,origin", Map.class, headers);
        Map<String, Object> results = response.getBody();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(((Integer) results.get("totalResults"))).isPositive();
        List<Map<String, Object>> list = (List<Map<String, Object>>) results.get("resources");
        boolean found = false;
        for (Map<String, Object> user : list) {
            assertThat(user)
                    .containsKey("id")
                    .containsKey("userName")
                    .containsKey(OriginKeys.ORIGIN)
                    .doesNotContainKey("name")
                    .doesNotContainKey("emails");
            if (user.get("userName").equals(username)) {
                found = true;
                assertThat(user).containsEntry(OriginKeys.ORIGIN, origin);
            }
        }
        assertThat(found).isTrue();
    }

    private String getScimReadBearerToken() {
        HttpHeaders accessTokenHeaders = new HttpHeaders();
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((testAccounts.getAdminClientId() + ":" + testAccounts.getAdminClientSecret()).getBytes()));
        accessTokenHeaders.add("Authorization", basicDigestHeaderValue);

        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("client_id", testAccounts.getAdminClientId());
        params.add("scope", "scim.read");
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, accessTokenHeaders);
        return (String) tokenResponse.getBody().get("access_token");
    }

    private String getLoginReadBearerToken() {
        HttpHeaders accessTokenHeaders = new HttpHeaders();
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64("login:loginsecret".getBytes()));
        accessTokenHeaders.add("Authorization", basicDigestHeaderValue);

        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "client_credentials");
        params.add("client_id", "login");
        params.add("scope", "oauth.login");
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap(serverRunning.getAccessTokenUri(), params, accessTokenHeaders);
        return (String) tokenResponse.getBody().get("access_token");
    }

    @SuppressWarnings("rawtypes")
    ResponseEntity<Map> authenticate(String username, String password, Map<String, Object> additionalParams) {
        RestTemplate restTemplate = new RestTemplate();
        // The default java.net client doesn't allow you to handle 4xx responses
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        if (restTemplate instanceof OAuth2RestTemplate oAuth2RestTemplate) {
            oAuth2RestTemplate.setErrorHandler(new UaaOauth2ErrorHandler(oAuth2RestTemplate.getResource(), HttpStatus.Series.SERVER_ERROR));
        } else {
            restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
                @Override
                protected boolean hasError(HttpStatusCode statusCode) {
                    return statusCode.is5xxServerError();
                }
            });
        }
        HttpHeaders headers = new HttpHeaders();
        if (additionalParams != null) {
            headers.add("Authorization", "Bearer " + getLoginReadBearerToken());
        }
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, Object> parameters = new LinkedMultiValueMap<>();
        parameters.set("username", username);
        if (password != null) {
            parameters.set("password", password);
        }
        if (additionalParams != null) {
            parameters.setAll(additionalParams);
        }

        return restTemplate.exchange(serverRunning.getUrl("/authenticate"),
                HttpMethod.POST, new HttpEntity<MultiValueMap<String, Object>>(parameters, headers), Map.class);
    }
}
