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
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalLoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken.ID_TOKEN;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.validate;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.getNoValidatingClientHttpRequestFactory;

public class XOAuthAuthenticationManager extends ExternalLoginAuthenticationManager<XOAuthAuthenticationManager.AuthenticationData> {

    private RestTemplate restTemplate = new RestTemplate();
    private IdentityProviderProvisioning providerProvisioning;

    public XOAuthAuthenticationManager(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    protected AuthenticationData getExternalAuthenticationDetails(Authentication authentication) {

        XOAuthCodeToken codeToken = (XOAuthCodeToken) authentication;
        setOrigin(codeToken.getOrigin());
        IdentityProvider provider = providerProvisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());

        if (provider != null && provider.getConfig() instanceof AbstractXOAuthIdentityProviderDefinition) {
            AuthenticationData authenticationData = new AuthenticationData();

            AbstractXOAuthIdentityProviderDefinition config = (AbstractXOAuthIdentityProviderDefinition) provider.getConfig();
            Map<String, Object> claims = getClaimsFromToken(codeToken, config);

            if (claims == null) {
                return null;
            }
            authenticationData.setClaims(claims);

            Map<String, Object> attributeMappings = config.getAttributeMappings();

            String userNameAttributePrefix = (String) attributeMappings.get(USER_NAME_ATTRIBUTE_NAME);
            String username;
            if (StringUtils.hasText(userNameAttributePrefix)) {
                username = (String) claims.get(userNameAttributePrefix);
            } else {
                username = (String) claims.get("preferred_username");
            }

            authenticationData.setUsername(username);

            authenticationData.setAuthorities(extractXOAuthUserAuthorities(attributeMappings, claims));

            return authenticationData;
        }

        return null;
    }

    @Override
    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, AuthenticationData authenticationData) {
        super.populateAuthenticationAttributes(authentication, request, authenticationData);

        Map<String, Object> claims = authenticationData.getClaims();
        if (claims != null) {
            if(claims.get("amr") != null) {
                authentication.getAuthenticationMethods().addAll((Collection<String>) claims.get("amr"));
            }
        }
    }

    @Override
    protected UaaUser getUser(Authentication request, AuthenticationData authenticationData) {
        if (authenticationData != null) {

            Map<String, Object> claims = authenticationData.getClaims();
            String username = authenticationData.getUsername();
            String email = (String) claims.get("email");
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
                .withAuthorities(authenticationData.getAuthorities())
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
        boolean is_invitation_acceptance = isAcceptedInvitationAuthentication();
        String email = userFromRequest.getEmail();

        if (is_invitation_acceptance) {
            String invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
            userFromDb = getUserDatabase().retrieveUserById(invitedUserId);
            if ( email != null ) {
                if (!email.equalsIgnoreCase(userFromDb.getEmail()) ) {
                    throw new BadCredentialsException("OAuth User email mismatch. Authenticated email doesn't match invited email.");
                }
            }
            publish(new InvitedUserAuthenticatedEvent(userFromDb));
            userFromDb = getUserDatabase().retrieveUserById(invitedUserId);
        }

        //we must check and see if the email address has changed between authentications
        if (request.getPrincipal() !=null) {
            if (haveUserAttributesChanged(userFromDb, userFromRequest)) {
                userFromDb = userFromDb.modifyAttributes(email, userFromRequest.getGivenName(), userFromRequest.getFamilyName(), userFromRequest.getPhoneNumber()).modifyUsername(userFromRequest.getUsername());
                userModified = true;
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, userFromRequest.getAuthorities(), true);
        publish(event);
        return getUserDatabase().retrieveUserById(userFromDb.getId());
    }

    @Override
    protected boolean isAddNewShadowUser() {
        if(!super.isAddNewShadowUser()) return false;
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> provider = providerProvisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
        return provider.getConfig().isAddShadowUserOnLogin();
    }

    protected boolean isAcceptedInvitationAuthentication() {
        try {
            RequestAttributes attr = RequestContextHolder.currentRequestAttributes();
            if (attr!=null) {
                Boolean result = (Boolean) attr.getAttribute("IS_INVITE_ACCEPTANCE", RequestAttributes.SCOPE_SESSION);
                if (result!=null) {
                    return result.booleanValue();
                }
            }
        } catch (IllegalStateException x) {
            //nothing bound on thread.
            logger.debug("Unable to retrieve request attributes during SAML authentication.");

        }
        return false;
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

        String tokenKey = config.getTokenKey();
        URL tokenKeyUrl = config.getTokenKeyUrl();
        if(!StringUtils.hasText(tokenKey) && tokenKeyUrl != null && StringUtils.hasText(tokenKeyUrl.toString())) {
            tokenKey = getTokenKeyFromOAuth(config, tokenKeyUrl.toString());
        }

        TokenValidation validation = validate(idToken)
            .checkSignature(new CommonSignatureVerifier(tokenKey))
            .checkIssuer((StringUtils.isEmpty(config.getIssuer()) ? config.getTokenUrl().toString() : config.getIssuer()))
            .checkAudience(config.getRelyingPartyId())
            .checkExpiry()
            .throwIfInvalid();
        Jwt decodeIdToken = validation.getJwt();

        return JsonUtils.readValue(decodeIdToken.getClaims(), new TypeReference<Map<String, Object>>(){});
    }

    private String getTokenKeyFromOAuth(AbstractXOAuthIdentityProviderDefinition config, String tokenKeyUrl) {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", getClientAuthHeader(config));
        headers.add("Accept", "application/json");
        HttpEntity tokenKeyRequest = new HttpEntity<>(null, headers);
        ResponseEntity<Map<String, Object>> responseEntity = restTemplate.exchange(tokenKeyUrl, HttpMethod.GET, tokenKeyRequest, new ParameterizedTypeReference<Map<String, Object>>() {});
        return (String) responseEntity.getBody().get("value");
    }

    private String getTokenFromCode(XOAuthCodeToken codeToken, AbstractXOAuthIdentityProviderDefinition config) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("response_type", getResponseType(config));
        body.add("code", codeToken.getCode());
        body.add("redirect_uri", codeToken.getRedirectUrl());

        HttpHeaders headers = new HttpHeaders();
        String clientAuthHeader = getClientAuthHeader(config);
        headers.add("Authorization", clientAuthHeader);
        headers.add("Accept", "application/json");

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

    private String getClientAuthHeader(AbstractXOAuthIdentityProviderDefinition config) {
        String clientAuth = new String(Base64.encodeBase64((config.getRelyingPartyId() + ":" + config.getRelyingPartySecret()).getBytes()));
        return "Basic " + clientAuth;
    }

    protected static class AuthenticationData {

        private Map<String, Object> claims;
        private String username;
        private List<? extends GrantedAuthority> authorities;

        public void setClaims(Map<String,Object> claims) {
            this.claims = claims;
        }

        public Map<String, Object> getClaims() {
            return claims;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getUsername() {
            return username;
        }


        public List<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<? extends GrantedAuthority> authorities) {
            this.authorities = authorities;
        }
    }
}
