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

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.CommonSignatureVerifier;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TokenValidation;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken.ID_TOKEN;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_PREFIX;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.validate;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.getNoValidatingClientHttpRequestFactory;

public class XOAuthAuthenticationManager extends ExternalLoginAuthenticationManager {

    private RestTemplate restTemplate = new RestTemplate();
    private IdentityProviderProvisioning providerProvisioning;

    public XOAuthAuthenticationManager(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    protected UaaUser getUser(Authentication request) {
        XOAuthCodeToken codeToken = (XOAuthCodeToken) request;
        setOrigin(codeToken.getOrigin());
        IdentityProvider provider = providerProvisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());

        if (provider != null && provider.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition) {
            AbstractXOAuthIdentityProviderDefinition config = (AbstractXOAuthIdentityProviderDefinition) provider.getConfig();
            Map<String, Object> claims = getClaimsFromToken(codeToken, config);
            if (claims == null) {
                return null;
            }

            Map<String, Object> attributeMappings = config.getAttributeMappings();

            String email = (String) claims.get("email");

            String username;
            String userNameAttributePrefix = (String) attributeMappings.get(USER_NAME_ATTRIBUTE_PREFIX);
            if (StringUtils.hasText(userNameAttributePrefix)) {
                username = (String) claims.get(userNameAttributePrefix);
            } else {
                username = (String) claims.get("preferred_username");
            }

            if (email == null) {
                email = generateEmailIfNull(username);
            }

            return new UaaUser(
                new UaaUserPrototype()
                    .withEmail(email)
                    .withGivenName((String) claims.get("given_name"))
                    .withFamilyName((String) claims.get("family_name"))
                    .withPhoneNumber((String) claims.get("phone_number"))
                    .withModified(new Date())
                    .withUsername(username)
                    .withPassword("")
                    .withAuthorities(extractXOAuthUserAuthorities(attributeMappings, claims))
                    .withCreated(new Date())
                    .withOrigin(getOrigin())
                    .withExternalId(null)
                    .withVerified(true)
                    .withZoneId(IdentityZoneHolder.get().getId())
                    .withSalt(null)
                    .withPasswordLastModified(null));
        }
        return null;
    }

    private List<? extends GrantedAuthority> extractXOAuthUserAuthorities(Map<String, Object> attributeMappings , Map<String, Object> claims) {
        List<String> groupNames = new LinkedList<>();
        if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof String) {
            groupNames.add((String) attributeMappings.get(GROUP_ATTRIBUTE_NAME));
        } else if (attributeMappings.get(GROUP_ATTRIBUTE_NAME) instanceof Collection) {
            groupNames.addAll((Collection) attributeMappings.get(GROUP_ATTRIBUTE_NAME));
        }

        Set<String> scopes = new HashSet<>();
        for (String g : groupNames) {
            Object roles = claims.get(g);
            if (roles instanceof String) {
                scopes.addAll(Arrays.asList(((String) roles).split(",")));
            } else if (roles instanceof Collection) {
                scopes.addAll((Collection<? extends String>) roles);
            }
        }

        List<XOAuthUserAuthority> authorities = new ArrayList<>();
        for (String scope : scopes) {
            authorities.add(new XOAuthUserAuthority(scope));
        }

        return authorities;
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        boolean userModified = false;
        //we must check and see if the email address has changed between authentications
        if (request.getPrincipal() !=null) {
            if (haveUserAttributesChanged(userFromDb, userFromRequest)) {
                userFromDb = userFromDb.modifyAttributes(userFromRequest.getEmail(), userFromRequest.getGivenName(), userFromRequest.getFamilyName(), userFromRequest.getPhoneNumber()).modifyUsername(userFromRequest.getUsername());
                userModified = true;
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, userFromRequest.getAuthorities(), true);
        publish(event);
        return getUserDatabase().retrieveUserById(userFromDb.getId());
    }

    @Override
    protected boolean isAddNewShadowUser() {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> provider = providerProvisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
        return provider.getConfig().isAddShadowUserOnLogin();
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
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

    private Map<String,Object> getClaimsFromToken(XOAuthCodeToken codeToken, AbstractXOAuthIdentityProviderDefinition config) {
        String idToken = getTokenFromCode(codeToken, config);
        if(idToken == null) {
            return null;
        }
        TokenValidation validation = validate(idToken)
            .checkSignature(new CommonSignatureVerifier(config.getTokenKey()))
            .checkIssuer(config.getTokenUrl().toString())
            .checkAudience(config.getRelyingPartyId())
            .checkExpiry()
            .throwIfInvalid();
        Jwt decodeIdToken = validation.getJwt();

        return JsonUtils.readValue(decodeIdToken.getClaims(), new TypeReference<Map<String, Object>>(){});
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
        headers.put("Accept", Collections.singletonList("application/json"));

        URI requestUri;
        HttpEntity requestEntity = new HttpEntity<>(body, headers);
        try {
            requestUri = config.getTokenUrl().toURI();
        } catch (URISyntaxException e) {
            return null;
        }

        try {
            if (config.isSkipSslValidation()) {
                restTemplate.setRequestFactory(getNoValidatingClientHttpRequestFactory());
            }
            ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestUri, HttpMethod.POST, requestEntity, new ParameterizedTypeReference<Map<String, String>>() {});
            return responseEntity.getBody().get(ID_TOKEN);
        } catch (HttpServerErrorException|HttpClientErrorException ex) {
            throw ex;
        }
    }
}
