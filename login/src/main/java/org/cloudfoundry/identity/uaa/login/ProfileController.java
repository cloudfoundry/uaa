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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * @author Vidya Valmikinathan
 */
@Controller
public class ProfileController {

    private final ApprovalsService approvalsService;

    @Autowired
    public ProfileController(ApprovalsService approvalsService) {
        this.approvalsService = approvalsService;
    }

    /**
     * Display the current user's approvals
     */
    @RequestMapping(value = "/profile", method = RequestMethod.GET)
    public String get(Authentication authentication, Model model) {
        Map<String, List<UaaApprovalsService.DescribedApproval>> approvals = approvalsService.getCurrentApprovalsByClientId();
        model.addAttribute("approvals", approvals);
        model.addAttribute("isUaaManagedUser", isUaaManagedUser(authentication));
        return "approvals";
    }

    /**
     * Handle form post for revoking chosen approvals
     */
    @RequestMapping(value = "/profile", method = RequestMethod.POST)
    public String post(@RequestParam(required = false) Collection<String> checkedScopes,
                       @RequestParam(required = false) String update,
                       @RequestParam(required = false) String delete,
                       @RequestParam(required = false) String clientId) {

        if (null != update) {
            Map<String, List<UaaApprovalsService.DescribedApproval>> approvalsByClientId = approvalsService.getCurrentApprovalsByClientId();

            List<UaaApprovalsService.DescribedApproval> allApprovals = new ArrayList<UaaApprovalsService.DescribedApproval>();
            for (List<UaaApprovalsService.DescribedApproval> clientApprovals : approvalsByClientId.values()) {
                allApprovals.addAll(clientApprovals);
            }

            for (Approval approval : allApprovals) {
                String namespacedScope = approval.getClientId() + "-" + approval.getScope();
                if (checkedScopes != null && checkedScopes.contains(namespacedScope)) {
                    approval.setStatus(Approval.ApprovalStatus.APPROVED);
                } else {
                    approval.setStatus(Approval.ApprovalStatus.DENIED);
                }
            }

            approvalsService.updateApprovals(allApprovals);
        }
        else if (null != delete) {
            approvalsService.deleteApprovalsForClient(clientId);
        }

        return "redirect:profile";
    }

    private boolean isUaaManagedUser(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UaaPrincipal) {
            UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
            return Origin.UAA.equals(principal.getOrigin());
        }
        return false;
    }
}
