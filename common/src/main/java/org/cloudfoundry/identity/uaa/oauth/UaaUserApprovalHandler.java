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

import java.util.*;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.TokenServicesUserApprovalHandler;

/**
 * @author Dave Syer
 * 
 */
public class UaaUserApprovalHandler extends TokenServicesUserApprovalHandler {

	private Collection<String> autoApproveClients = new HashSet<String>();

	private Map<String, Collection<String>> autoApproveClientScopes = new HashMap<String, Collection<String>>();

	private boolean useTokenServices = true;

	/**
	 * @param useTokenServices the useTokenServices to set
	 */
	public void setUseTokenServices(boolean useTokenServices) {
		this.useTokenServices = useTokenServices;
	}

	/**
	 * @param autoApproveClients the auto approve clients to set
	 */
	public void setAutoApproveClients(String[] autoApproveClients) {
		this.autoApproveClients = Arrays.asList(autoApproveClients);
	}

	public void setAutoApproveClientScopes(Map<String, Collection<String>> autoApproveClientScopes) {
		this.autoApproveClientScopes = autoApproveClientScopes;
		if (this.autoApproveClientScopes == null) {
			this.autoApproveClientScopes = Collections.emptyMap();
		}
	}

	/**
	 * Allows automatic approval for a white list of clients in the implicit grant case.
	 * 
	 * @param authorizationRequest The authorization request.
	 * @param userAuthentication the current user authentication
	 * 
	 * @return Whether the specified request has been approved by the current user.
	 */
	public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		if (useTokenServices && super.isApproved(authorizationRequest, userAuthentication)) {
			return true;
		}
		if (!userAuthentication.isAuthenticated()) {
			return false;
		}
//		return authorizationRequest.isApproved() || autoApproveClients.contains(authorizationRequest.getClientId());
		String clientId = authorizationRequest.getClientId();
		Collection<String> requestedScopes = authorizationRequest.getScope();
		return authorizationRequest.isApproved()
				|| autoApproveClients.contains(clientId)
				|| (autoApproveClientScopes.containsKey(clientId) && autoApproveClientScopes.get(clientId).containsAll(requestedScopes));
	}

}
