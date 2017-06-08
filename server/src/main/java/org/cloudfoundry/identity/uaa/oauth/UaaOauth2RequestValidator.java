/*******************************************************************************
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

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenRequest;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;

public class UaaOauth2RequestValidator implements OAuth2RequestValidator {

    private static String CLIENT_CREDENTIALS = "client_credentials";
    private ClientServicesExtension clientDetailsService;

    public void setClientDetailsService(ClientServicesExtension clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) throws InvalidScopeException {
        if (CLIENT_CREDENTIALS.equalsIgnoreCase(authorizationRequest.getRequestParameters().get(OAuth2Utils.GRANT_TYPE))) {
            validateScope(authorizationRequest.getScope(), getAuthorities(client.getAuthorities()), false);
        } else {
            validateScope(authorizationRequest.getScope(), client.getScope(), true);
        }
    }

    public void validateScope(TokenRequest tokenRequest, ClientDetails client) throws InvalidScopeException {
        if (CLIENT_CREDENTIALS.equalsIgnoreCase(tokenRequest.getGrantType())) {
            validateScope(tokenRequest.getScope(), getAuthorities(client.getAuthorities()), false);
        } else if (GRANT_TYPE_USER_TOKEN.equalsIgnoreCase(tokenRequest.getGrantType())) {
            client = clientDetailsService.loadClientByClientId(tokenRequest.getRequestParameters().get(CLIENT_ID), IdentityZoneHolder.get().getId());
            validateScope(tokenRequest.getScope(), client.getScope(), true);
        } else {
            validateScope(tokenRequest.getScope(), client.getScope(), true);
        }
    }

    private void validateScope(Set<String> requestScopes, Set<String> clientScopes, boolean wildCardsAllowed) {

        if (clientScopes == null || clientScopes.isEmpty()) {
            throw new InvalidScopeException("Empty scope (client has no registered scopes)");
        }

        if (wildCardsAllowed) {
            Set<Pattern> wildcards = UaaStringUtils.constructWildcards(clientScopes);
            for (String scope : requestScopes) {
                if (!UaaStringUtils.matches(wildcards, scope)) {
                    throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
                }
            }
        } else {
            for (String scope : requestScopes) {
                if (!clientScopes.contains(scope)) {
                    throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
                }
            }
        }

    }

    private Set<String> getAuthorities(Collection<GrantedAuthority> authorities) {
        Set<String> result = new HashSet<>();
        for (GrantedAuthority authority : authorities) {
            result.add(authority.getAuthority());
        }
        return result;
    }

}
