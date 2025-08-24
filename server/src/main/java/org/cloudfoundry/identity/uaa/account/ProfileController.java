package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.DescribedApproval;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.util.StringUtils.hasText;

@Controller
public class ProfileController {

    protected static Logger logger = LoggerFactory.getLogger(ProfileController.class);

    private final ApprovalStore approvalsService;
    private final MultitenantClientServices clientDetailsService;
    private final SecurityContextAccessor securityContextAccessor;
    private final IdentityZoneManager identityZoneManager;

    public ProfileController(final ApprovalStore approvalsService,
            final MultitenantClientServices clientDetailsService,
            final SecurityContextAccessor securityContextAccessor,
            final IdentityZoneManager identityZoneManager) {
        this.approvalsService = approvalsService;
        this.clientDetailsService = clientDetailsService;
        this.securityContextAccessor = securityContextAccessor;
        this.identityZoneManager = identityZoneManager;
    }

    /**
     * Display the current user's approvals
     */
    @GetMapping("/profile")
    public String get(Authentication authentication, Model model) {
        Map<String, List<DescribedApproval>> approvals = getCurrentApprovalsForUser(getCurrentUserId());
        Map<String, String> clientNames = getClientNames(approvals);
        model.addAttribute("clientnames", clientNames);
        model.addAttribute("approvals", approvals);
        extractUaaUserAttributes(authentication, model);
        return "approvals";
    }

    /**
     * Handle form post for revoking chosen approvals
     */
    @PostMapping("/profile")
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
        } else if (null != delete) {
            deleteApprovalsForClient(userId, clientId);
        }

        return "redirect:profile";
    }

    @ExceptionHandler
    public View handleException(NoSuchClientException nsce) {
        logger.debug("Unable to find client for approvals:{}", nsce.getMessage());
        return new RedirectView("profile?error_message_code=request.invalid_parameter", true);
    }

    private Map<String, String> getClientNames(Map<String, List<DescribedApproval>> approvals) {
        Map<String, String> clientNames = new LinkedHashMap<>();
        for (String clientId : approvals.keySet()) {
            ClientDetails details = clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
            String name = details.getClientId();
            if (details.getAdditionalInformation() != null && details.getAdditionalInformation().get(ClientConstants.CLIENT_NAME) != null) {
                name = (String) details.getAdditionalInformation().get(ClientConstants.CLIENT_NAME);
            }
            clientNames.put(clientId, name);
        }
        return clientNames;
    }

    private void extractUaaUserAttributes(Authentication authentication, Model model) {
        if (authentication.getPrincipal() instanceof UaaPrincipal principal) {
            boolean isUaaManagedUser = OriginKeys.UAA.equals(principal.getOrigin());
            model.addAttribute("isUaaManagedUser", isUaaManagedUser);
            if (isUaaManagedUser) {
                model.addAttribute("email", principal.getEmail());
            }
            return;
        }

        model.addAttribute("isUaaManagedUser", false);
    }

    private Map<String, List<DescribedApproval>> getCurrentApprovalsForUser(String userId) {
        Map<String, List<DescribedApproval>> result = new HashMap<>();
        List<Approval> approvalsResponse = approvalsService.getApprovalsForUser(userId, identityZoneManager.getCurrentIdentityZoneId());

        List<DescribedApproval> approvals = new ArrayList<>();
        for (Approval approval : approvalsResponse) {
            DescribedApproval describedApproval = new DescribedApproval(approval);
            approvals.add(describedApproval);
        }

        for (DescribedApproval approval : approvals) {
            List<DescribedApproval> clientApprovals = result.computeIfAbsent(
                    approval.getClientId(),
                    k -> new ArrayList<>()
            );

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
            approvalList.sort(Comparator.comparing(Approval::getScope));
        }
        return result;
    }

    private void updateApprovals(List<DescribedApproval> approvals) {
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        for (DescribedApproval approval : approvals) {
            approvalsService.revokeApprovalsForClientAndUser(approval.getClientId(), approval.getUserId(), zoneId);
        }
        for (DescribedApproval approval : approvals) {
            approvalsService.addApproval(approval, zoneId);
        }
    }

    private void deleteApprovalsForClient(String userId, String clientId) {
        clientDetailsService.loadClientByClientId(clientId);
        approvalsService.revokeApprovalsForClientAndUser(clientId, userId, identityZoneManager.getCurrentIdentityZoneId());
    }

    private String getCurrentUserId() {
        if (!securityContextAccessor.isUser()) {
            throw new AccessDeniedException("Approvals can only be managed by a user");
        }
        return securityContextAccessor.getUserId();
    }

}
