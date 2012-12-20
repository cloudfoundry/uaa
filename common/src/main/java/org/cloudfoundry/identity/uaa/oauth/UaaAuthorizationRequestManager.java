/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.AuthorizationRequestManager;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;

/**
 * An {@link AuthorizationRequestManager} that applies various UAA-specific rules to an authorization request,
 * validating it and setting the default values for scopes and resource ids.
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
	 * Default scopes that are always added to a user token (and then removed if the client doesn't have permission).
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
	 * A map from scope name to resource id, for cases (like openid) that cannot be extracted from the scope name.
	 *
	 * @param scopeToResource the map to use
	 */
	public void setScopesToResources(Map<String, String> scopeToResource) {
		this.scopeToResource = new HashMap<String, String>(scopeToResource);
	}

	/**
	 * The string used to separate resource ids from feature names in scopes (e.g. "cloud_controller.read").
	 *
	 * @param scopeSeparator the scope separator to set. Default is period "."
	 */
	public void setScopeSeparator(String scopeSeparator) {
		this.scopeSeparator = scopeSeparator;
	}

	/**
	 * Create an authorization request applying various UAA rules to the authorizationParameters and the registered
	 * client details.
	 * <ul>
	 * <li>For client_credentials grants, the default scopes are the client's granted authorities</li>
	 * <li>For other grant types the default scopes are the registered scopes in the client details</li>
	 * <li>Only scopes in those lists are valid, otherwise there is an exception</li>
	 * <li>If the scopes contain separators then resource ids are extracted as the scope value up to the last index of
	 * the separator</li>
	 * <li>Some scopes can be hard-wired to resource ids (like the open id connect values), in which case the separator
	 * is ignored</li>
	 * </ul>
	 *
	 * @see org.springframework.security.oauth2.provider.AuthorizationRequestFactory#createAuthorizationRequest(java.util.Map,
	 * java.lang.String, java.lang.String, java.util.Set)
	 */
	@Override
	public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {

		String clientId = authorizationParameters.get("client_id");
		BaseClientDetails clientDetails = new BaseClientDetails(clientDetailsService.loadClientByClientId(clientId));

		Set<String> scopes = OAuth2Utils.parseParameterList(authorizationParameters.get("scope"));
		String grantType = authorizationParameters.get("grant_type");
		if ((scopes == null || scopes.isEmpty())) {
			if ("client_credentials".equals(grantType)) {
				// The client authorities should be a list of scopes
				scopes = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
			}
			else {
				// The default for a user token is the scopes registered with the client
				scopes = clientDetails.getScope();
			}
		}

		if (!"client_credentials".equals(grantType) && securityContextAccessor.isUser()) {
			scopes = checkUserScopes(scopes, securityContextAccessor.getAuthorities(), clientDetails);
		}

		Set<String> resourceIds = getResourceIds(clientDetails, scopes);
		clientDetails.setResourceIds(resourceIds);
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest(authorizationParameters);
		if (!scopes.isEmpty()) {
			request.setScope(scopes);
		}
		request.addClientDetails(clientDetails);

		return request;

	}

	/**
	 * Apply UAA rules to validate the requested scope. For client credentials grants the valid scopes are actually in
	 * the authorities of the client.
	 *
	 * @see org.springframework.security.oauth2.provider.endpoint.ParametersValidator#validateParameters(java.util.Map,
	 * org.springframework.security.oauth2.provider.ClientDetails)
	 */
	@Override
	public void validateParameters(Map<String, String> parameters, ClientDetails clientDetails) {
		if (parameters.containsKey("scope")) {
			Set<String> validScope = clientDetails.getScope();
			if ("client_credentials".equals(parameters.get("grant_type"))) {
				validScope = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
			}
			for (String scope : OAuth2Utils.parseParameterList(parameters.get("scope"))) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope
							+ ". Did you know that you can get default scopes by simply sending no value?", validScope);
				}
			}
		}
		// Client id is not mandatory in the request, but if it's there we can prevent a clash
		if (parameters.containsKey("grant_type") && parameters.containsKey("client_id")) {
			String clientId = parameters.get("client_id");
			if (!clientDetails.getClientId().equals(clientId)) {
				throw new BadClientCredentialsException();
			}
		}
	}

	/**
	 * Add or remove scopes derived from the current authenticated user's authorities (if any)
	 *
	 * @param scopes the initial set of scopes from the client registration
	 * @param clientDetails
	 * @param collection the users authorities
	 * @return modified scopes adapted according to the rules specified
	 */
	private Set<String> checkUserScopes(Set<String> scopes, Collection<? extends GrantedAuthority> authorities,
			ClientDetails clientDetails) {

		Set<String> result = new LinkedHashSet<String>(scopes);
		Set<String> allowed = new LinkedHashSet<String>(AuthorityUtils.authorityListToSet(authorities));

		// Add in all default scopes
		allowed.addAll(defaultScopes);
		// Find intersection of user authorities, default scopes and client scopes:
		for (Iterator<String> iter = allowed.iterator(); iter.hasNext();) {
			String scope = iter.next();
			if (!clientDetails.getScope().contains(scope)) {
				iter.remove();
			}
		}

		// Weed out disallowed scopes:
		for (Iterator<String> iter = result.iterator(); iter.hasNext();) {
			String scope = iter.next();
			if (!allowed.contains(scope)) {
				iter.remove();
			}
		}

		// Check that a token with empty scope is not going to be granted
		if (result.isEmpty() && !clientDetails.getScope().isEmpty()) {
			throw new InvalidScopeException(
					"Invalid scope (empty) - this user is not allowed any of the requested scopes: " + scopes
							+ " (either you requested a scope that was not allowed or client '"
							+ clientDetails.getClientId() + "' is not allowed to act on behalf of this user)", allowed);
		}

		return result;

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
