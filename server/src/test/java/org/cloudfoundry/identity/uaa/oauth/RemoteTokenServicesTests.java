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
package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Dave Syer
 */
class RemoteTokenServicesTests {

    private final RemoteTokenServices services = new RemoteTokenServices();

    private final Map<String, Object> body = new HashMap<>();

    private final HttpHeaders headers = new HttpHeaders();

    private final HttpStatus status = HttpStatus.OK;

    public RemoteTokenServicesTests() {
        services.setClientId("client");
        services.setClientSecret("secret");
        body.put(ClaimConstants.CLIENT_ID, "remote");
        body.put(ClaimConstants.USER_NAME, "olds");
        body.put(ClaimConstants.EMAIL, "olds@vmware.com");
        body.put(ClaimConstants.ISS, "http://some.issuer.com");
        body.put(ClaimConstants.USER_ID, "HDGFJSHGDF");
        services.setRestTemplate(new RestTemplate() {
            @SuppressWarnings("unchecked")
            @Override
            public <T> ResponseEntity<T> exchange(String url, HttpMethod method, HttpEntity<?> requestEntity,
                                                  Class<T> responseType, Object... uriVariables) throws RestClientException {
                return new ResponseEntity<>((T) body, headers, status);
            }
        });
    }

    @Test
    void tokenRetrieval() {
        OAuth2Authentication result = services.loadAuthentication("FOO");
        assertThat(result).isNotNull();
        assertThat(result.getOAuth2Request().getClientId()).isEqualTo("remote");
        assertThat(result.getUserAuthentication().getName()).isEqualTo("olds");
        assertThat(((RemoteUserAuthentication) result.getUserAuthentication()).getId()).isEqualTo("HDGFJSHGDF");
        assertThat(result.getOAuth2Request().getRequestParameters()).isNotNull()
                .doesNotContainKey(ClaimConstants.ISS);
    }

    @Test
    void tokenRetrievalWithClaims() {
        services.setStoreClaims(true);
        OAuth2Authentication result = services.loadAuthentication("FOO");
        assertThat(result).isNotNull();
        assertThat(result.getOAuth2Request().getClientId()).isEqualTo("remote");
        assertThat(result.getUserAuthentication().getName()).isEqualTo("olds");
        assertThat(((RemoteUserAuthentication) result.getUserAuthentication()).getId()).isEqualTo("HDGFJSHGDF");
        assertThat(result.getOAuth2Request().getRequestParameters()).isNotNull()
                .containsKey(ClaimConstants.ISS);
    }

    @Test
    void tokenRetrievalWithClientAuthorities() {
        body.put("client_authorities", Collections.singleton("uaa.none"));
        OAuth2Authentication result = services.loadAuthentication("FOO");
        assertThat(result).isNotNull();
        assertThat(result.getOAuth2Request().getAuthorities()).hasToString("[uaa.none]");
    }

    @Test
    void tokenRetrievalWithUserAuthorities() {
        body.put("user_authorities", Collections.singleton("uaa.user"));
        OAuth2Authentication result = services.loadAuthentication("FOO");
        assertThat(result).isNotNull();
        assertThat(result.getUserAuthentication().getAuthorities()).hasToString("[uaa.user]");
    }

    @Test
    void noBodyReceived() {
        RestTemplate restTemplate = mock(RestTemplate.class);
        ResponseEntity responseEntity = mock(ResponseEntity.class);
        when(restTemplate.exchange(anyString(), (HttpMethod) any(), any(), (Class) any())).thenReturn(responseEntity);
        when(responseEntity.getBody()).thenReturn(null);
        services.setRestTemplate(restTemplate);
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> services.loadAuthentication("FOO"));
    }

    @Test
    void tokenRetrievalWithAdditionalAuthorizationAttributes() {
        Map<String, Integer> additionalAuthorizationAttributesMap = Map.of("test", 1);
        body.put(ClaimConstants.ADDITIONAL_AZ_ATTR, additionalAuthorizationAttributesMap);

        OAuth2Authentication result = services.loadAuthentication("FOO");

        assertThat(result).isNotNull();
        assertThat(result.getOAuth2Request()
                .getRequestParameters()).containsEntry(ClaimConstants.ADDITIONAL_AZ_ATTR, JsonUtils.writeValueAsString(additionalAuthorizationAttributesMap));
    }
}
