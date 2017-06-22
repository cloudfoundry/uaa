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
package org.cloudfoundry.identity.uaa.account;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.DescribedApproval;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.util.StringUtils.hasText;

@Controller
public class ProfileController {

    protected static Log logger = LogFactory.getLog(ProfileController.class);

    private final ApprovalStore approvalsService;
    private final ClientServicesExtension clientDetailsService;
    private final SecurityContextAccessor securityContextAccessor;

    public ProfileController(ApprovalStore approvalsService,
                             ClientServicesExtension clientDetailsService) {
        this(approvalsService, clientDetailsService, new DefaultSecurityContextAccessor());
    }

    public ProfileController(ApprovalStore approvalsService,
                             ClientServicesExtension clientDetailsService,
                             SecurityContextAccessor securityContextAccessor) {
        this.approvalsService = approvalsService;
        this.clientDetailsService = clientDetailsService;
        this.securityContextAccessor = securityContextAccessor;
    }

    /**
     * Display the current user's approvals
     */
    @RequestMapping(value = "/profile", method = RequestMethod.GET)
    public String get(Authentication authentication, Model model) {
        Map<String, List<DescribedApproval>> approvals = getCurrentApprovalsForUser(getCurrentUserId());
        Map<String, String> clientNames = getClientNames(approvals);
        model.addAttribute("clientnames", clientNames);
        model.addAttribute("approvals", approvals);
        model.addAttribute("isUaaManagedUser", isUaaManagedUser(authentication));
        return "approvals";
    }

    protected Map<String, String> getClientNames(Map<String, List<DescribedApproval>> approvals) {
        Map<String, String> clientNames = new LinkedHashMap<>();
        for (String clientId : approvals.keySet()) {
            ClientDetails details = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
            String name = details.getClientId();
            if (details.getAdditionalInformation()!=null && details.getAdditionalInformation().get(ClientConstants.CLIENT_NAME)!=null) {
                name = (String)details.getAdditionalInformation().get(ClientConstants.CLIENT_NAME);
            }
            clientNames.put(clientId, name);
        }
        return clientNames;
    }

    /**
     * Handle form post for revoking chosen approvals
     */
    @RequestMapping(value = "/profile", method = RequestMethod.POST)
    public String post(@RequestParam(required = false) Collection<String> checkedScopes,
                       @RequestParam(required = false) String update,
                       @RequestParam(required = false) String delete,
                       @RequestParam(required = false) String clientId) {
        String userId = getCurrentUserId();
        if (null != update) {
            Map<String, List<DescribedApproval>> approvalsByClientId = getCurrentApprovalsForUser(userId);

            List<DescribedApproval> allApprovals = new ArrayList<>();
            for (List<DescribedApproval> clientApprovals : approvalsByClientId.values()) {
                allApprovals.addAll(clientApprovals);
            }

            if (hasText(clientId)) {
                allApprovals.removeIf(da -> !clientId.equals(da.getClientId()));
            }

            for (Approval approval : allApprovals) {
                String namespacedScope = approval.getClientId() + "-" + approval.getScope();
                if (checkedScopes != null && checkedScopes.contains(namespacedScope)) {
                    approval.setStatus(Approval.ApprovalStatus.APPROVED);
                } else {
                    approval.setStatus(Approval.ApprovalStatus.DENIED);
                }
            }
            updateApprovals(allApprovals);
        }
        else if (null != delete) {
            deleteApprovalsForClient(userId, clientId);
        }

        return "redirect:profile";
    }

    @ExceptionHandler
    public View handleException(NoSuchClientException nsce) {
        logger.debug("Unable to find client for approvals:"+nsce.getMessage());
        return new RedirectView("profile?error_message_code=request.invalid_parameter", true);
    }

    private boolean isUaaManagedUser(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
            return OriginKeys.UAA.equals(principal.getOrigin());
        }
        return false;
    }

    public Map<String, List<DescribedApproval>> getCurrentApprovalsForUser(String userId) {
        Map<String, List<DescribedApproval>> result = new HashMap<>();
        List<Approval> approvalsResponse = approvalsService.getApprovalsForUser(userId, IdentityZoneHolder.get().getId());

        List<DescribedApproval> approvals = new ArrayList<>();
        for (Approval approval : approvalsResponse) {
            DescribedApproval describedApproval = new DescribedApproval(approval);
            approvals.add(describedApproval);
        }

        for (DescribedApproval approval : approvals) {
            List<DescribedApproval> clientApprovals = result.get(approval.getClientId());
            if (clientApprovals == null) {
                clientApprovals = new ArrayList<>();
                result.put(approval.getClientId(), clientApprovals);
            }

            String scope = approval.getScope();
            if (!scope.contains(".")) {
                approval.setDescription("Access your data with scope '" + scope + "'");
                clientApprovals.add(approval);
            } else {
                String resource = scope.substring(0, scope.lastIndexOf("."));
                String access = scope.substring(scope.lastIndexOf(".") + 1);
                approval.setDescription("Access your '" + resource + "' resources with scope '" + access + "'");
                clientApprovals.add(approval);
            }
        }
        for (List<DescribedApproval> approvalList : result.values()) {
            Collections.sort(approvalList, new Comparator<DescribedApproval>() {
                @Override
                public int compare(DescribedApproval o1, DescribedApproval o2) {
                    return o1.getScope().compareTo(o2.getScope());
                }
            });
        }
        return result;
    }

    public void updateApprovals(List<DescribedApproval> approvals) {
        String zoneId = IdentityZoneHolder.get().getId();
        for (DescribedApproval approval : approvals) {
            approvalsService.revokeApprovalsForClientAndUser(approval.getClientId(), approval.getUserId(), zoneId);
        }
        for (DescribedApproval approval : approvals) {
            approvalsService.addApproval(approval, zoneId);
        }
    }

    public void deleteApprovalsForClient(String userId, String clientId) {
        clientDetailsService.loadClientByClientId(clientId);
        approvalsService.revokeApprovalsForClientAndUser(clientId, userId, IdentityZoneHolder.get().getId());
    }

    private String getCurrentUserId() {
        if (!securityContextAccessor.isUser()) {
            throw new AccessDeniedException("Approvals can only be managed by a user");
        }
        return securityContextAccessor.getUserId();
    }

}
