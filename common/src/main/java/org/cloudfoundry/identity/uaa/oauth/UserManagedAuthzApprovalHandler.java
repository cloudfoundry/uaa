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

import static org.cloudfoundry.identity.uaa.oauth.authz.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.oauth.authz.Approval.ApprovalStatus.DENIED;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.authz.Approval;
import org.cloudfoundry.identity.uaa.oauth.authz.ApprovalStore;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

public class UserManagedAuthzApprovalHandler implements
		UserApprovalHandler {

	private static Log logger = LogFactory.getLog(UserManagedAuthzApprovalHandler.class);

	private final String approvalParameter = AuthorizationRequest.USER_OAUTH_APPROVAL;

	private ApprovalStore approvalStore = null;

	private ClientDetailsService clientDetailsService;

	//Default approval expiry is one month
	private long approvalExpirySeconds = oneMonth();

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	private long oneMonth() {
		Calendar cal = Calendar.getInstance();
		cal.setTime(new Date());
		cal.set(Calendar.MONTH, (cal.get(Calendar.MONTH) + 6));
		return cal.getTimeInMillis();
	}

	public void setApprovalStore(ApprovalStore approvalStore) {
		this.approvalStore = approvalStore;
	}

	@Override
	public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,	Authentication userAuthentication) {
		return authorizationRequest;
	}

	@Override
	public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {

		String flag = authorizationRequest.getApprovalParameters().get(approvalParameter);
		boolean userApproval = flag != null && flag.toLowerCase().equals("true");

		if (logger.isDebugEnabled()) {
			StringBuilder builder = new StringBuilder("Looking up user approved authorizations for ");
			builder.append("client_id=" + authorizationRequest.getClientId());
			builder.append(" and username=" + userAuthentication.getName());
			logger.debug(builder.toString());
		}

		Collection<String> requestedScopes = authorizationRequest.getScope();

		if(userApproval) {
			//Store the scopes that have been approved / denied
			Date expiry = new Date(System.currentTimeMillis() + (approvalExpirySeconds * 1000));

			//Get the approved scopes, calculate the denied scope
			Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
			Set<String> approvedScopes = new HashSet<String>();
			for(String approvalParameter : approvalParameters.keySet()) {
				if(approvalParameter.startsWith("scope.")) {
					approvedScopes.add(approvalParameters.get(approvalParameter).substring("scope.".length()));
				}
			}

			((DefaultAuthorizationRequest) authorizationRequest).setScope(approvedScopes);

			for(String requestedScope : requestedScopes) {
				if(approvedScopes.contains(requestedScope)) {
					approvalStore.addApproval(new Approval(userAuthentication.getName(),
												authorizationRequest.getClientId(),
												requestedScope,
												expiry,
												APPROVED));
				} else {
					approvalStore.addApproval(new Approval(userAuthentication.getName(),
												authorizationRequest.getClientId(),
												requestedScope,
												expiry,
												DENIED));
				}
			}

			if(userAuthentication.isAuthenticated()) {
				return true;
			}

		} else {
			//Find the stored approvals for that user and client
			List<Approval> userApprovals =
					approvalStore.getApprovals(userAuthentication.getName(),
													authorizationRequest.getClientId());

			//Look at the scopes and see if they have expired
			Set<String> validUserApprovedScopes = new HashSet<String>();
			Set<String> approvedScopes = new HashSet<String>();
			Date today = new Date();
			for(Approval approval : userApprovals) {
				if(approval.getExpiresAt().after(today)) {
					validUserApprovedScopes.add(approval.getScope());
					if(approval.getStatus() == APPROVED) {
						approvedScopes.add(approval.getScope());
					}
				}
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Valid user approved/denied scopes are " + validUserApprovedScopes);
			}

			//If the requested scopes have already been approved/denied by the user, this request is approved
			if(validUserApprovedScopes.containsAll(requestedScopes) && userAuthentication.isAuthenticated()) {
				//Set only the scopes that have been approved by the user
				((DefaultAuthorizationRequest) authorizationRequest).setScope(approvedScopes);
				return true;
			}
		}

		//If this client is auto approved, approve the request. We check this later because
		//we still want to store the approvals that the user recorded.
		String clientId = authorizationRequest.getClientId();
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
			if (isAutoApprove(client, requestedScopes)) {
				userApproval = true;
			}
		}

		return userApproval;
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

	public void setApprovalExpirySeconds(long approvalExpirySeconds) {
		this.approvalExpirySeconds = approvalExpirySeconds;
	}

}
