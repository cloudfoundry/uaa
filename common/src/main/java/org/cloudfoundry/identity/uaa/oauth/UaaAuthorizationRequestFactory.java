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
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.AuthorizationRequestFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * An {@link AuthorizationRequestFactory} that applies various UAA-specific rules to an authorization request,
 * validating it and setting the default values for scopes and resource ids.
 * 
 * @author Dave Syer
 * 
 */
public class UaaAuthorizationRequestFactory implements AuthorizationRequestFactory {

	private final ClientDetailsService clientDetailsService;

	private Map<String, String> scopeToResource = Collections.singletonMap("openid", "openid");

	private String scopeSeparator = ".";

	public UaaAuthorizationRequestFactory(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
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
	 * Create an authorization request applying various UAA rules to the input and the registered client details.
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
	public AuthorizationRequest createAuthorizationRequest(Map<String, String> parameters, String clientId,
			String grantType, Set<String> scopes) {
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, clientDetails);
		if (scopes != null) {
			validateScope(clientDetails, scopes, grantType);
		}
		if (scopes == null || scopes.isEmpty()) {
			if (grantType.equals("client_credentials")) {
				// The client authorities should be a list of scopes
				scopes = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
			}
			else {
				// The default for a user token is the scopes registered with the client
				scopes = clientDetails.getScope();
			}
		}
		Set<String> resourceIds = getResourceIds(clientDetails, scopes);
		AuthorizationRequest request = new AuthorizationRequest(parameters, clientId, scopes,
				clientDetails.getAuthorities(), resourceIds);
		return request;

	}

	private Set<String> getResourceIds(ClientDetails clientDetails, Set<String> scopes) {
		Set<String> resourceIds = new LinkedHashSet<String>();
		for (String scope : scopes) {
			if (scopeToResource.containsKey(scope)) {
				resourceIds.add(scopeToResource.get(scope));
			}
			else if (scope.contains(scopeSeparator) && !scope.endsWith(scopeSeparator)) {
				resourceIds.add(scope.substring(0, scope.lastIndexOf(scopeSeparator)));
			}
		}
		return resourceIds.isEmpty() ? clientDetails.getResourceIds() : resourceIds;
	}

	private void validateScope(ClientDetails clientDetails, Set<String> scopes, String grantType) {

		Set<String> validScope = clientDetails.getScope();
		if (grantType.equals("client_credentials")) {
			validScope = AuthorityUtils.authorityListToSet(clientDetails.getAuthorities());
		}
		else {
			validScope = clientDetails.getScope();
		}

		if (clientDetails.isScoped()) {
			for (String scope : scopes) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope, validScope);
				}
			}
		}

	}

	private void validateGrantType(String grantType, ClientDetails clientDetails) {
		Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
		if (authorizedGrantTypes != null && !authorizedGrantTypes.isEmpty()
				&& !authorizedGrantTypes.contains(grantType)) {
			throw new InvalidGrantException("Unauthorized grant type: " + grantType);
		}
	}

}
