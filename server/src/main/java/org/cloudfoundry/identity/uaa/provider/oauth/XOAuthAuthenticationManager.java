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
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken.ID_TOKEN;

public class XOAuthAuthenticationManager extends ExternalLoginAuthenticationManager {

    private RestTemplate restTemplate = new RestTemplate();
    private IdentityProviderProvisioning providerProvisioning;
    private String currentOrigin;

    public XOAuthAuthenticationManager(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return super.authenticate(authentication);
    }

    @Override
    protected UaaUser getUser(Authentication request) {
        XOAuthCodeToken codeToken = (XOAuthCodeToken) request;
        setCurrentOrigin(codeToken.getOrigin());
        String origin = codeToken.getOrigin();
        IdentityProvider provider = providerProvisioning.retrieveByOrigin(origin, IdentityZoneHolder.get().getId());

        if (provider != null && provider.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition) {
            Claims claims = getClaimsFromToken(codeToken, (AbstractXOAuthIdentityProviderDefinition) provider.getConfig());
            String email = claims.getEmail();
            String username = claims.getUserName();
            if (email == null) {
                email = generateEmailIfNull(username);
            }

            return new UaaUser(
                new UaaUserPrototype()
                    .withEmail(email)
                    .withGivenName(claims.getGivenName())
                    .withFamilyName(claims.getFamilyName())
                    .withPhoneNumber(claims.getPhoneNumber())
                    .withModified(new Date())
                    .withUsername(claims.getUserName())
                    .withPassword("")
                    .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                    .withCreated(new Date())
                    .withOrigin(origin)
                    .withExternalId(null)
                    .withVerified(true)
                    .withZoneId(IdentityZoneHolder.get().getId())
                    .withSalt(null)
                    .withPasswordLastModified(null));
        }
        return null;
    }

    @Override
    public String getOrigin() {
        return currentOrigin;
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }

    public void setCurrentOrigin(String currentOrigin) {
        this.currentOrigin = currentOrigin;
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

    private Claims getClaimsFromToken(XOAuthCodeToken codeToken, AbstractXOAuthIdentityProviderDefinition config) {
        String id_token = getTokenFromCode(codeToken, config);
        Jwt decodeIdToken = JwtHelper.decode(id_token);

        Claims claims = JsonUtils.readValue(decodeIdToken.getClaims(), Claims.class);
        return claims;
    }

    private String getTokenFromCode(XOAuthCodeToken codeToken, AbstractXOAuthIdentityProviderDefinition config) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("response_type", getResponseType(config));
        body.add("code", codeToken.getCode());
        body.add("redirect_uri", codeToken.getRedirectUrl());

        HttpHeaders headers = new HttpHeaders();
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        headers.put("Authorization", Collections.singletonList("Basic " + clientAuth));
        headers.put("Content-Type", Collections.singletonList("application/json"));
        headers.put("Accept", Collections.singletonList("application/json"));

        URI requestUri;
        HttpEntity requestEntity = new HttpEntity<>(body, headers);
        try {
            requestUri = config.getTokenUrl().toURI();
        } catch (URISyntaxException e) {
            return null;
        }

        ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestUri, HttpMethod.POST, requestEntity, new ParameterizedTypeReference<Map<String, String>>() {});
        return responseEntity.getBody().get(ID_TOKEN);
    }
}
