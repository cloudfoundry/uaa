package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OidcAuthenticationFlow;
import org.cloudfoundry.identity.uaa.provider.XOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken.ID_TOKEN;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class XOAuthAuthenticationManager implements AuthenticationManager {

    private RestTemplate restTemplate = new RestTemplate();
    private IdentityProviderProvisioning providerProvisioning;

    public XOAuthAuthenticationManager(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        XOAuthCodeToken codeToken = (XOAuthCodeToken) authentication;

        String origin = codeToken.getOrigin();
        String code = codeToken.getCode();
        IdentityProvider provider = providerProvisioning.retrieveByOrigin(origin, IdentityZoneHolder.get().getId());
        if (provider != null && provider.getConfig() instanceof XOAuthIdentityProviderDefinition) {
            XOAuthIdentityProviderDefinition config = (XOAuthIdentityProviderDefinition) provider.getConfig();
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", config.getRelyingPartyId());
            body.add("client_secret", config.getRelyingPartySecret());
            body.add("grant_type", "authorization_code");
            body.add("response_type", config.getAuthenticationFlow().getResponseType());
            body.add("code", code);
            body.add("redirect_uri", codeToken.getRedirectUrl());

            HttpHeaders headers = new HttpHeaders();
            headers.put("Content-Type", Arrays.asList("application/x-www-form-urlencoded"));
            headers.put("Accept", Arrays.asList("application/json"));

            URI requestUri;
            HttpEntity requestEntity = new HttpEntity<>(body, headers);
            try {
                requestUri = config.getTokenUrl().toURI();
            } catch (URISyntaxException e) {
                return null;
            }

            ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestUri, HttpMethod.POST, requestEntity, new ParameterizedTypeReference<Map<String, String>>() {});
            String id_token = responseEntity.getBody().get(ID_TOKEN);

            OidcAuthenticationFlow authenticationFlow = (OidcAuthenticationFlow) config.getAuthenticationFlow();

            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.add("Authorization", "bearer " + id_token);

            ResponseEntity<Map<String, String>> userInfoResponseEntity = restTemplate.exchange(authenticationFlow.getUserInfoUrl().toString(), HttpMethod.GET, new HttpEntity<>(null ,userInfoHeaders), new ParameterizedTypeReference<Map<String, String>>() {});

            Claims claims = JsonUtils.readValue(JsonUtils.writeValueAsString(userInfoResponseEntity.getBody()), Claims.class);

            UaaUser user = new UaaUser(claims.getUserName(), null, claims.getEmail(), claims.getGivenName(), claims.getFamilyName(), origin, IdentityZoneHolder.get().getId());
            UaaPrincipal principal = new UaaPrincipal(user);
            UaaAuthentication uaaAuthentication = new UaaAuthentication(principal, codeToken.getAuthorities(), null);
            return uaaAuthentication;
        }

        return null;
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }
}
