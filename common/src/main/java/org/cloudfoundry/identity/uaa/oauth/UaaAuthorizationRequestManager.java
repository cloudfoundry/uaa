/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.AuthorizationRequestManager;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;

/**
 * An {@link AuthorizationRequestManager} that applies various UAA-specific
 * rules to an authorization request,
 * validating it and setting the default values for requestedScopes and resource ids.
 * 
 * @author Dave Syer
 * 
 */
public class UaaAuthorizationRequestManager implements AuthorizationRequestManager {

    private final ClientDetailsService clientDetailsService;

    private Map<String, String> scopeToResource = Collections.singletonMap("openid", "openid");

    private String scopeSeparator = ".";

    private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

    private Collection<String> defaultScopes = new HashSet<String>();

    public UaaAuthorizationRequestManager(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * Default requestedScopes that are always added to a user token (and then removed if
     * the client doesn't have permission).
     * 
     * @param defaultScopes the defaultScopes to set
     */
    public void setDefaultScopes(Collection<String> defaultScopes) {
        this.defaultScopes = defaultScopes;
    }

    /**
     * A helper to pull stuff out of the current security context.
     * 
     * @param securityContextAccessor the securityContextAccessor to set
     */
    public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        this.securityContextAccessor = securityContextAccessor;
    }

    /**
     * A map from scope name to resource id, for cases (like openid) that cannot
     * be extracted from the scope name.
     * 
     * @param scopeToResource the map to use
     */
    public void setScopesToResources(Map<String, String> scopeToResource) {
        this.scopeToResource = new HashMap<String, String>(scopeToResource);
    }

    /**
     * The string used to separate resource ids from feature names in requestedScopes
     * (e.g. "cloud_controller.read").
     * 
     * @param scopeSeparator the scope separator to set. Default is period "."
     */
    public void setScopeSeparator(String scopeSeparator) {
        this.scopeSeparator = scopeSeparator;
    }

    /**
     * Create an authorization request applying various UAA rules to the
     * authorizationParameters and the registered
     * client details.
     * <ul>
     * <li>For client_credentials grants, the default requestedScopes are the client's
     * granted authorities</li>
     * <li>For other grant types the default requestedScopes are the registered requestedScopes in
     * the client details</li>
     * <li>Only requestedScopes in those lists are valid, otherwise there is an exception
     * </li>
     * <li>If the requestedScopes contain separators then resource ids are extracted as
     * the scope value up to the last index of the separator</li>
     * <li>Some requestedScopes can be hard-wired to resource ids (like the open id
     * connect values), in which case the separator is ignored</li>
     * </ul>
     * 
     */
    @Override
    public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {

        String clientId = authorizationParameters.get("client_id");
        BaseClientDetails clientDetails = new BaseClientDetails(clientDetailsService.loadClientByClientId(clientId));

        Set<String> scopes = OAuth2Utils.parseParameterList(authorizationParameters.get("scope"));
        String grantType = authorizationParameters.get("grant_type");
        if ((scopes == null || scopes.isEmpty())) {
            if ("client_credentials".equals(grantType)) {
                // The client authorities should be a list of requestedScopes
                scopes = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
            }
            else {
                // The default for a user token is the requestedScopes registered with
                // the client
                scopes = clientDetails.getScope();
            }
        }

        Set<String> scopesFromExternalAuthorities = null;
        if (!"client_credentials".equals(grantType) && securityContextAccessor.isUser()) {
            scopes = checkUserScopes(scopes, securityContextAccessor.getAuthorities(), clientDetails);

            // TODO: will the grantType ever contain client_credentials or
            // authorization_code
            // External Authorities are things like LDAP groups that will be
            // mapped to Oauth requestedScopes
            // Add those requestedScopes to the request. These requestedScopes will not be
            // validated against the requestedScopes
            // registered to a client.
            // These requestedScopes also do not need approval. The fact that they are
            // already in an external
            // group communicates user approval. Denying approval does not mean
            // much
            scopesFromExternalAuthorities = findScopesFromAuthorities(authorizationParameters.get("authorities"));
        }

        Set<String> resourceIds = getResourceIds(clientDetails, scopes);
        clientDetails.setResourceIds(resourceIds);
        DefaultAuthorizationRequest request = new DefaultAuthorizationRequest(authorizationParameters);
        if (!scopes.isEmpty()) {
            request.setScope(scopes);
        }
        if (scopesFromExternalAuthorities != null) {
            Map<String, String> existingAuthorizationParameters = new LinkedHashMap<String, String>();
            existingAuthorizationParameters.putAll(request.getAuthorizationParameters());
            existingAuthorizationParameters.put("external_scopes",
                            OAuth2Utils.formatParameterList(scopesFromExternalAuthorities));
            request.setAuthorizationParameters(existingAuthorizationParameters);
        }

        request.addClientDetails(clientDetails);

        return request;
    }

    private Set<String> findScopesFromAuthorities(String authorities) {
        return new HashSet<String>();
    }

    /**
     * Apply UAA rules to validate the requestedScopes scope. For client credentials
     * grants the valid requestedScopes are actually in
     * the authorities of the client.
     * 
     * @see org.springframework.security.oauth2.provider.endpoint.ParametersValidator#validateParameters(java.util.Map,
     *      org.springframework.security.oauth2.provider.ClientDetails)
     */
    @Override
    public void validateParameters(Map<String, String> parameters, ClientDetails clientDetails) {
        if (parameters.containsKey("scope")) {
            Set<String> validScope = clientDetails.getScope();
            if ("client_credentials".equals(parameters.get("grant_type"))) {
                validScope = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
            }
            Set<Pattern> validWildcards = constructWildcards(validScope);
            Set<String> scopes = OAuth2Utils.parseParameterList(parameters.get("scope"));
            for (String scope : scopes) {
                if (!matches(validWildcards, scope)) {
                    throw new InvalidScopeException("Invalid scope: " + scope
                                    + ". Did you know that you can get default requestedScopes by simply sending no value?",
                                    validScope);
                }
            }
        }
    }

    /**
     * Add or remove requestedScopes derived from the current authenticated user's
     * authorities (if any)
     * 
     * @param requestedScopes the initial set of requestedScopes from the client registration
     * @param clientDetails
     * @param collection the users authorities
     * @return modified requestedScopes adapted according to the rules specified
     */
    private Set<String> checkUserScopes(Set<String> requestedScopes, Collection<? extends GrantedAuthority> authorities,
                    ClientDetails clientDetails) {
        Set<String> allowed = new LinkedHashSet<>(AuthorityUtils.authorityListToSet(authorities));
        // Add in all default requestedScopes
        allowed.addAll(defaultScopes);

        // Find intersection of user authorities, default requestedScopes and client requestedScopes:
        Set<String> result = intersectScopes(new LinkedHashSet<>(requestedScopes), clientDetails.getScope(), allowed);

        // Check that a token with empty scope is not going to be granted
        if (result.isEmpty() && !clientDetails.getScope().isEmpty()) {
            throw new InvalidScopeException(
                "Invalid scope (empty) - this user is not userScopes any of the requestedScopes requestedScopes: " + requestedScopes
                + " (either you requestedScopes a scope that was not userScopes or client '"
                + clientDetails.getClientId()
                + "' is not userScopes to act on behalf of this user)", allowed);
        }

        return result;
    }

    protected Set<String> intersectScopes(Set<String> requestedScopes, Set<String> clientScopes, Set<String> userScopes) {
        Set<String> result = new HashSet<>(userScopes);

        Set<Pattern> clientWildcards = constructWildcards(clientScopes);
        for (Iterator<String> iter = result.iterator(); iter.hasNext();) {
            String scope = iter.next();
            if (!matches(clientWildcards, scope)) {
                iter.remove();
            }
        }

        Set<Pattern> requestedWildcards = constructWildcards(requestedScopes);
        // Weed out disallowed requestedScopes:
        for (Iterator<String> iter = result.iterator(); iter.hasNext();) {
            String scope = iter.next();
            if (!matches(requestedWildcards, scope)) {
                iter.remove();
            }
        }

        return result;
    }

    protected Set<Pattern> constructWildcards(Set<String> scopes) {
        return UaaStringUtils.constructWildcards(scopes);
    }

    protected boolean matches(Set<Pattern> wildcards, String scope) {
        return UaaStringUtils.matches(wildcards, scope);
    }

    private Set<String> getResourceIds(ClientDetails clientDetails, Set<String> scopes) {
        Set<String> resourceIds = new LinkedHashSet<String>();
        for (String scope : scopes) {
            if (scopeToResource.containsKey(scope)) {
                resourceIds.add(scopeToResource.get(scope));
            }
            else if (scope.contains(scopeSeparator) && !scope.endsWith(scopeSeparator) && !scope.equals("uaa.none")) {
                String id = scope.substring(0, scope.lastIndexOf(scopeSeparator));
                resourceIds.add(id);
            }
        }
        return resourceIds.isEmpty() ? clientDetails.getResourceIds() : resourceIds;
    }



}
