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

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class UserManagedAuthzApprovalHandler implements UserApprovalHandler {

    private static final String SCOPE_PREFIX = "scope.";

    private static Log logger = LogFactory.getLog(UserManagedAuthzApprovalHandler.class);

    private final String approvalParameter = OAuth2Utils.USER_OAUTH_APPROVAL;

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
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {

        String flag = authorizationRequest.getApprovalParameters().get(approvalParameter);
        boolean userApproval = flag != null && flag.toLowerCase().equals("true");

        if (logger.isDebugEnabled()) {
            StringBuilder builder = new StringBuilder("Looking up user approved authorizations for ");
            builder.append("client_id=").append(authorizationRequest.getClientId());
            builder.append(" and username=").append(userAuthentication.getName());
            logger.debug(builder.toString());
        }

        Collection<String> requestedScopes = authorizationRequest.getScope();

        // Factor in auto approved scopes
        Set<String> autoApprovedScopes = new HashSet<>();
        BaseClientDetails client = (BaseClientDetails) clientDetailsService.retrieve(authorizationRequest.getClientId());
        if (client != null && requestedScopes != null) {
            autoApprovedScopes.addAll(client.getAutoApproveScopes());
            autoApprovedScopes = UaaTokenUtils.retainAutoApprovedScopes(requestedScopes, autoApprovedScopes);
        }
        //translate scope to user scopes - including wild cards

        if (userApproval) {
            // Store the scopes that have been approved / denied
            Date expiry = computeExpiry();

            // Get the approved scopes, calculate the denied scope
            Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
            Set<String> approvedScopes = new HashSet<>();
            approvedScopes.addAll(autoApprovedScopes);
            boolean foundUserApprovalParameter = false;
            for (String approvalParameter : approvalParameters.keySet()) {
                if (approvalParameter.startsWith(SCOPE_PREFIX)) {
                    approvedScopes.add(approvalParameters.get(approvalParameter).substring(SCOPE_PREFIX.length()));
                    foundUserApprovalParameter = true;
                }
            }

            if (foundUserApprovalParameter) {
                authorizationRequest.setScope(approvedScopes);

                for (String requestedScope : requestedScopes) {
                    if (approvedScopes.contains(requestedScope)) {
                        Approval approval = new Approval()
                            .setUserId(getUserId(userAuthentication))
                            .setClientId(authorizationRequest.getClientId())
                            .setScope(requestedScope)
                            .setExpiresAt(expiry)
                            .setStatus(APPROVED);
                        approvalStore.addApproval(approval);
                    }
                    else {
                        Approval approval = new Approval()
                            .setUserId(getUserId(userAuthentication))
                            .setClientId(authorizationRequest.getClientId())
                            .setScope(requestedScope)
                            .setExpiresAt(expiry)
                            .setStatus(DENIED);
                        approvalStore.addApproval(approval);
                    }
                }

            }
            else { // Deny all except auto approved scopes
                authorizationRequest.setScope(autoApprovedScopes);

                for (String requestedScope : requestedScopes) {
                    if (!autoApprovedScopes.contains(requestedScope)) {
                        Approval approval = new Approval()
                            .setUserId(getUserId(userAuthentication))
                            .setClientId(authorizationRequest.getClientId())
                            .setScope(requestedScope)
                            .setExpiresAt(expiry)
                            .setStatus(DENIED);
                        approvalStore.addApproval(approval);
                    }
                }
            }

            if (userAuthentication.isAuthenticated()) {
                return true;
            }

        } else {
            // Find the stored approvals for that user and client
            List<Approval> userApprovals = approvalStore.getApprovals(getUserId(userAuthentication), authorizationRequest.getClientId());

            // Look at the scopes and see if they have expired
            Set<String> validUserApprovedScopes = new HashSet<>();
            Set<String> approvedScopes = new HashSet<>();
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

            // If the requested scopes have already been acted upon by the user,
            // this request is approved
            if (validUserApprovedScopes.containsAll(requestedScopes) && userAuthentication.isAuthenticated()) {
                approvedScopes = UaaTokenUtils.retainAutoApprovedScopes(requestedScopes, approvedScopes);
                // Set only the scopes that have been approved by the user
                authorizationRequest.setScope(approvedScopes);
                return true;
            }
        }

        return false;
    }

    protected String getUserId(Authentication authentication) {
        return Origin.getUserId(authentication);
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

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        return authorizationRequest;
    }

    @Override
    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        return authorizationRequest;
    }

    @Override
    public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        Map<String, Object> model = new HashMap<String, Object>();
        model.putAll(authorizationRequest.getRequestParameters());
        return model;
    }
}
