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

package org.cloudfoundry.identity.uaa.provider.oauth;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
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
        if (provider != null && provider.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition) {
            AbstractXOAuthIdentityProviderDefinition config = (AbstractXOAuthIdentityProviderDefinition) provider.getConfig();
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "authorization_code");
            body.add("response_type", getResponseType(config));
            body.add("code", code);
            body.add("redirect_uri", codeToken.getRedirectUrl());

            HttpHeaders headers = new HttpHeaders();
            String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
            headers.put("Authorization", Collections.singletonList("Basic " + clientAuth));
            headers.put("Content-Type", Collections.singletonList("application/x-www-form-urlencoded"));
            headers.put("Accept", Collections.singletonList("application/json"));

            URI requestUri;
            HttpEntity requestEntity = new HttpEntity<>(body, headers);
            try {
                requestUri = config.getTokenUrl().toURI();
            } catch (URISyntaxException e) {
                return null;
            }

            ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestUri, HttpMethod.POST, requestEntity, new ParameterizedTypeReference<Map<String, String>>() {});
            String id_token = responseEntity.getBody().get(ID_TOKEN);

            Jwt decodeIdToken =  JwtHelper.decode(id_token);

            Claims claims = JsonUtils.readValue(decodeIdToken.getClaims(), Claims.class);
            UaaUser user = new UaaUser(claims.getUserName(), null, claims.getEmail(), claims.getGivenName(), claims.getFamilyName(), origin, IdentityZoneHolder.get().getId());
            UaaPrincipal principal = new UaaPrincipal(user);
            UaaAuthentication uaaAuthentication = new UaaAuthentication(principal, codeToken.getAuthorities(), null);
            return uaaAuthentication;
        }

        return null;
    }

    private String getResponseType(AbstractXOAuthIdentityProviderDefinition config) {
        if (RawXOAuthIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            return "token";
        } else if (XOIDCIdentityProviderDefinition.class.isAssignableFrom(config.getClass())) {
            return "id_token";
        } else {
            throw new IllegalArgumentException("Unknown type for provider.");
        }
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }
}
