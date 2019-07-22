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
package org.cloudfoundry.identity.uaa.approval;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

//@Controller
public class ApprovalsAdminEndpoints implements InitializingBean, ApprovalsControllerService {

    private ApprovalStore approvalStore = null;

    private MultitenantClientServices clientDetailsService = null;

    private UaaUserDatabase userDatabase;

    private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

    private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
                    new HttpMessageConverter<?>[0]);

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final SecurityContextAccessor securityContextAccessor;

    public ApprovalsAdminEndpoints(final SecurityContextAccessor securityContextAccessor) {
        this.securityContextAccessor = securityContextAccessor;
    }

    public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
        this.statuses = statuses;
    }

    public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
        this.messageConverters = messageConverters;
    }

    public void setApprovalStore(ApprovalStore approvalStore) {
        this.approvalStore = approvalStore;
    }

    public void setUaaUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    @RequestMapping(value = "/approvals", method = RequestMethod.GET)
    @ResponseBody
    @Override
    public List<Approval> getApprovals(@RequestParam(required = false, defaultValue = "user_id pr") String ignored,
                                       @RequestParam(required = false, defaultValue = "1") int startIndex,
                                       @RequestParam(required = false, defaultValue = "100") int count) {
        String userId = getCurrentUserId();
        logger.debug("Fetching all approvals for user: " + userId);
        List<Approval> input = approvalStore.getApprovalsForUser(userId, IdentityZoneHolder.get().getId());
        List<Approval> approvals = UaaPagingUtils.subList(input, startIndex, count);

        // Find the clients for these approvals
        Set<String> clientIds = new HashSet<String>();
        for (Approval approval : approvals) {
            clientIds.add(approval.getClientId());
        }

        // Find the auto approved scopes for these clients
        Map<String, Set<String>> clientAutoApprovedScopes = new HashMap<String, Set<String>>();
        for (String clientId : clientIds) {
            BaseClientDetails client = (BaseClientDetails) clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());

            Set<String> autoApproved = client.getAutoApproveScopes();
            Set<String> autoApprovedScopes = new HashSet<String>();
            if (autoApproved != null) {
                if(autoApproved.contains("true")) {
                    autoApprovedScopes.addAll(client.getScope());
                } else {
                    autoApprovedScopes.addAll(autoApproved);
                }
            }

            clientAutoApprovedScopes.put(clientId, autoApprovedScopes);
        }

        List<Approval> filteredApprovals = new ArrayList<Approval>();
        // Remove auto approved scopes
        for (Approval approval : approvals) {
            if (!(clientAutoApprovedScopes.containsKey(approval.getClientId())
            && clientAutoApprovedScopes.get(approval.getClientId()).contains(approval.getScope()))) {
                filteredApprovals.add(approval);
            }
        }

        return filteredApprovals;
    }

    private String getCurrentUserId() {
        if (!securityContextAccessor.isUser()) {
            throw new AccessDeniedException("Approvals can only be managed by a user");
        }
        return securityContextAccessor.getUserId();
    }

    @RequestMapping(value = "/approvals", method = RequestMethod.PUT)
    @ResponseBody
    @Override
    public List<Approval> updateApprovals(@RequestBody Approval[] approvals) {
        String currentUserId = getCurrentUserId();
        logger.debug("Updating approvals for user: " + currentUserId);
        approvalStore.revokeApprovalsForUser(currentUserId, IdentityZoneHolder.get().getId());
        List<Approval> result = new LinkedList<>();
        for (Approval approval : approvals) {
            if (StringUtils.hasText(approval.getUserId()) &&  !isValidUser(approval.getUserId())) {
                logger.warn(String.format("Error[2] %s attempting to update approvals for %s", currentUserId, approval.getUserId()));
                throw new UaaException("unauthorized_operation", "Cannot update approvals for another user. Set user_id to null to update for existing user.",
                                HttpStatus.UNAUTHORIZED.value());
            } else {
                approval.setUserId(currentUserId);
            }
            if (approvalStore.addApproval(approval, IdentityZoneHolder.get().getId())) {
                result.add(approval);
            }
        }
        return result;
    }

    @RequestMapping(value = "/approvals/{clientId}", method = RequestMethod.PUT)
    @ResponseBody
    @Override
    public List<Approval> updateClientApprovals(@PathVariable String clientId, @RequestBody Approval[] approvals) {
        clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        String currentUserId = getCurrentUserId();
        logger.debug("Updating approvals for user: " + currentUserId);
        approvalStore.revokeApprovalsForClientAndUser(clientId, currentUserId, IdentityZoneHolder.get().getId());
        for (Approval approval : approvals) {
            if (StringUtils.hasText(approval.getUserId()) && !isValidUser(approval.getUserId())) {
                logger.warn(String.format("Error[1] %s attemting to update approvals for %s.", currentUserId, approval.getUserId()));
                throw new UaaException("unauthorized_operation", "Cannot update approvals for another user. Set user_id to null to update for existing user.",
                        HttpStatus.UNAUTHORIZED.value());
            } else {
                approval.setUserId(currentUserId);
            }
            approvalStore.addApproval(approval, IdentityZoneHolder.get().getId());
        }
        return approvalStore.getApprovals(currentUserId, clientId, IdentityZoneHolder.get().getId());
    }

    private boolean isValidUser(String userId) {
        if (userId == null || !userId.equals(getCurrentUserId())) {
            return false;
        }
        try {
            userDatabase.retrieveUserById(userId);
            return true;
        } catch (UsernameNotFoundException e) {
            return false;
        }
    }

    @RequestMapping(value = "/approvals", method = RequestMethod.DELETE)
    @ResponseBody
    @Override
    public ActionResult revokeApprovals(@RequestParam(required = true) String clientId) {
        clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        String userId = getCurrentUserId();
        logger.debug("Revoking all existing approvals for user: " + userId + " and client " + clientId);
        approvalStore.revokeApprovalsForClientAndUser(clientId, userId, IdentityZoneHolder.get().getId());
        return new ActionResult("ok", "Approvals of user " + userId + " and client " + clientId + " revoked");
    }

    @ExceptionHandler
    public View handleException(NoSuchClientException nsce) {
        logger.debug("Client not found:" + nsce.getMessage());
        return handleException(new UaaException(nsce.getMessage(), 404));
    }

    @ExceptionHandler
    public View handleException(Exception t) {
        UaaException e = t instanceof UaaException ? (UaaException) t : new UaaException("Unexpected error",
                        "Error accessing user's approvals", HttpStatus.INTERNAL_SERVER_ERROR.value());
        Class<?> clazz = t.getClass();
        for (Class<?> key : statuses.keySet()) {
            if (key.isAssignableFrom(clazz)) {
                e = new UaaException(t.getMessage(), "Error accessing user's approvals", statuses.get(key).value());
                break;
            }
        }
        return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, false),
                        HttpStatus.valueOf(e.getHttpStatus())), messageConverters);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(approvalStore, "Please supply an approvals manager");
        Assert.notNull(userDatabase, "Please supply a user database");
    }

    public void setClientDetailsService(MultitenantClientServices clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

}
