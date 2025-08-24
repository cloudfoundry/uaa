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

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
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
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
// public for YamlProcessorTest
public class ImplicitGrantIT {

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

    @Test
    void defaultScopes() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "cf");
        postBody.add("redirect_uri", "http://localhost:8080/redirect/cf");
        postBody.add("response_type", "token");
        postBody.add("source", "credentials");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/authorize",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

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

        Jwt accessToken = JwtHelper.decode(params.getFirst("access_token"));

        Map<String, Object> claims = JsonUtils.readValue(accessToken.getClaims(), new TypeReference<Map<String, Object>>() {
        });

        assertThat(claims).containsEntry("jti", params.getFirst("jti"))
                .containsEntry("client_id", "cf")
                .containsEntry("cid", "cf")
                .containsEntry("user_name", testAccounts.getUserName());
        assertThat(((List<String>) claims.get("scope"))).containsExactlyInAnyOrder(scopes);
        assertThat(((List<String>) claims.get("aud"))).containsExactlyInAnyOrder("scim", "openid", "cloud_controller", "password", "cf", "uaa");
    }

    @Test
    void invalidScopes() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", "cf");
        postBody.add("redirect_uri", "http://localhost:8080/redirect/cf");
        postBody.add("response_type", "token");
        postBody.add("source", "credentials");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());
        postBody.add("scope", "read");

        ResponseEntity<Void> responseEntity = restOperations.exchange(baseUrl + "/oauth/authorize",
                HttpMethod.POST,
                new HttpEntity<>(postBody, headers),
                Void.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        System.out.println("responseEntity.getHeaders().getLocation() = " + responseEntity.getHeaders().getLocation());

        UriComponents locationComponents = UriComponentsBuilder.fromUri(responseEntity.getHeaders().getLocation()).build();
        assertThat(locationComponents.getHost()).isEqualTo("localhost");
        assertThat(locationComponents.getPath()).isEqualTo("/redirect/cf");

        MultiValueMap<String, String> params = parseFragmentParams(locationComponents);

        assertThat(params.getFirst("error")).isEqualTo("invalid_scope");
        assertThat(params.getFirst("access_token")).isNullOrEmpty();
        assertThat(params.getFirst("credentials")).isNullOrEmpty();
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
