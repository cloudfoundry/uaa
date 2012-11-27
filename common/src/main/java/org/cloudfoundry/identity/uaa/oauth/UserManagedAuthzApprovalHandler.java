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
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.authz.Approval;
import org.cloudfoundry.identity.uaa.oauth.authz.ApprovalsStore;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

public class UserManagedAuthzApprovalHandler implements
		UserApprovalHandler {

	private static Log logger = LogFactory.getLog(UserManagedAuthzApprovalHandler.class);

	private final String approvalParameter = AuthorizationRequest.USER_OAUTH_APPROVAL;

	private ApprovalsStore approvalsStore = null;

	private ClientDetailsService clientDetailsService;

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public void setApprovalsStore(ApprovalsStore approvalsStore) {
		this.approvalsStore = approvalsStore;
	}

	@Override
	public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,	Authentication userAuthentication) {
		return authorizationRequest;
	}

	@Override
	public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {

		String flag = authorizationRequest.getApprovalParameters().get(approvalParameter);
		boolean approved = flag != null && flag.toLowerCase().equals("true");

		if (logger.isDebugEnabled()) {
			StringBuilder builder = new StringBuilder("Looking up user approved authorizations for ");
			builder.append("client_id=" + authorizationRequest.getClientId());
			builder.append(" and username=" + userAuthentication.getName());
			logger.debug(builder.toString());
		}

		Collection<String> requestedScopes = authorizationRequest.getScope();

		if(approved) {
			//Store the scopes that have been approved
			Date nextWeek = new Date(System.currentTimeMillis() + (86400 * 7 * 1000));
			for(String approvedScope : authorizationRequest.getScope()) {
				approvalsStore.addApproval(new Approval(userAuthentication.getName(),
															authorizationRequest.getClientId(),
															approvedScope,
															nextWeek));
			}
		} else {
			//Find the user in the authorizations table.
			List<Approval> userApprovals =
					approvalsStore.getApprovals(userAuthentication.getName(),
													authorizationRequest.getClientId());

			//Look at the scopes and see if they have expired
			Set<String> validUserApprovedScopes = new HashSet<String>();
			Date today = new Date();
			for(Approval approval : userApprovals) {
				if(approval.getExpiresAt().after(today)) {
					validUserApprovedScopes.add(approval.getScope());
				}
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Valid user approved scopes are " + validUserApprovedScopes);
			}

			//If the requested scopes have already been approved by the user, this request is approved
			if(validUserApprovedScopes.containsAll(requestedScopes) && userAuthentication.isAuthenticated()) {
				return true;
			}
		}

		if (approved && userAuthentication.isAuthenticated()) {
			return true;
		}

		String clientId = authorizationRequest.getClientId();
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
			if (isAutoApprove(client, requestedScopes)) {
				approved = true;
			}
		}

		return approved;
	}

	private boolean isAutoApprove(ClientDetails client, Collection<String> scopes) {
		Map<String, Object> info = client.getAdditionalInformation();
		if (info.containsKey("autoapprove")) {
			Object object = info.get("autoapprove");
			if (object instanceof Boolean && (Boolean) object || "true".equals(object)) {
				return true;
			}
			if (object instanceof Collection) {
				@SuppressWarnings("unchecked")
				Collection<String> autoScopes = (Collection<String>) object;
				if (autoScopes.containsAll(scopes)) {
					return true;
				}
			}
		}
		return false;
	}

}
