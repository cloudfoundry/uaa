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

import static org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus.DENIED;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

public class UserManagedAuthzApprovalHandler implements UserApprovalHandler {

	private static final String SCOPE_PREFIX = "scope.";

	private static Log logger = LogFactory.getLog(UserManagedAuthzApprovalHandler.class);

	private final String approvalParameter = AuthorizationRequest.USER_OAUTH_APPROVAL;

	private ApprovalStore approvalStore;

	private QueryableResourceManager<ClientDetails> clientDetailsService;

	private int approvalExpiryInMillis = -1;

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(QueryableResourceManager<ClientDetails> clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	public void setApprovalStore(ApprovalStore approvalStore) {
		this.approvalStore = approvalStore;
	}

	@Override
	public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,
			Authentication userAuthentication) {
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

		// Factor in auto approved scopes
		Set<String> autoApprovedScopes = new HashSet<String>();
		ClientDetails client = clientDetailsService.retrieve(authorizationRequest.getClientId());
		if (null != client) {
			Map<String, Object> additionalInfo = client.getAdditionalInformation();
			if (null != additionalInfo) {
				Object autoApproved = additionalInfo.get("autoapprove");
				if (autoApproved instanceof Collection<?>) {
					@SuppressWarnings("unchecked")
					Collection<? extends String> scopes = (Collection<? extends String>) autoApproved;
					autoApprovedScopes.addAll(scopes);
				}
				else if (autoApproved instanceof Boolean && (Boolean) autoApproved || "true".equals(autoApproved)) {
					autoApprovedScopes.addAll(client.getScope());
				}
			}
		}

		// Don't want to approve more than what's requested
		autoApprovedScopes.retainAll(requestedScopes);

		if (userApproval) {
			// Store the scopes that have been approved / denied
			Date expiry = computeExpiry();

			// Get the approved scopes, calculate the denied scope
			Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
			Set<String> approvedScopes = new HashSet<String>();
			approvedScopes.addAll(autoApprovedScopes);
			boolean foundUserApprovalParameter = false;
			for (String approvalParameter : approvalParameters.keySet()) {
				if (approvalParameter.startsWith(SCOPE_PREFIX)) {
					approvedScopes.add(approvalParameters.get(approvalParameter).substring(SCOPE_PREFIX.length()));
					foundUserApprovalParameter = true;
				}
			}

			if (foundUserApprovalParameter) {
				((DefaultAuthorizationRequest) authorizationRequest).setScope(approvedScopes);

				for (String requestedScope : requestedScopes) {
					if (approvedScopes.contains(requestedScope)) {
						approvalStore.addApproval(new Approval(userAuthentication.getName(), authorizationRequest
								.getClientId(), requestedScope, expiry, APPROVED));
					}
					else {
						approvalStore.addApproval(new Approval(userAuthentication.getName(), authorizationRequest
								.getClientId(), requestedScope, expiry, DENIED));
					}
				}

			}
			else { // Deny all except auto approved scopes
				((DefaultAuthorizationRequest) authorizationRequest).setScope(autoApprovedScopes);

				for (String requestedScope : requestedScopes) {
					if (!autoApprovedScopes.contains(requestedScope)) {
						approvalStore.addApproval(new Approval(userAuthentication.getName(), authorizationRequest
								.getClientId(), requestedScope, expiry, DENIED));
					}
				}
			}

			if (userAuthentication.isAuthenticated()) {
				return true;
			}

		}
		else {
			// Find the stored approvals for that user and client
			List<Approval> userApprovals = approvalStore.getApprovals(userAuthentication.getName(),
					authorizationRequest.getClientId());

			// Look at the scopes and see if they have expired
			Set<String> validUserApprovedScopes = new HashSet<String>();
			Set<String> approvedScopes = new HashSet<String>();
			approvedScopes.addAll(autoApprovedScopes);
			validUserApprovedScopes.addAll(autoApprovedScopes);
			Date today = new Date();
			for (Approval approval : userApprovals) {
				if (approval.getExpiresAt().after(today)) {
					validUserApprovedScopes.add(approval.getScope());
					if (approval.getStatus() == APPROVED) {
						approvedScopes.add(approval.getScope());
					}
				}
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Valid user approved/denied scopes are " + validUserApprovedScopes);
			}

			// If the requested scopes have already been acted upon by the user, this request is approved
			if (validUserApprovedScopes.containsAll(requestedScopes) && userAuthentication.isAuthenticated()) {
				approvedScopes.retainAll(requestedScopes);
				// Set only the scopes that have been approved by the user
				((DefaultAuthorizationRequest) authorizationRequest).setScope(approvedScopes);
				return true;
			}
		}

		return false;
	}

	private Date computeExpiry() {
		Calendar expiresAt = Calendar.getInstance();
		if (approvalExpiryInMillis == -1) { // use default of 1 month
			expiresAt.add(Calendar.MONTH, 1);
		}
		else {
			expiresAt.add(Calendar.MILLISECOND, approvalExpiryInMillis);
		}
		return expiresAt.getTime();
	}

	public void setApprovalExpiryInSeconds(int approvalExpirySeconds) {
		this.approvalExpiryInMillis = approvalExpirySeconds * 1000;
	}

}
