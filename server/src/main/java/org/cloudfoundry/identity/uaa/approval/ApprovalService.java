package org.cloudfoundry.identity.uaa.approval;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;

public class ApprovalService {
    TimeService timeService;
    ApprovalStore approvalStore;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public ApprovalService(TimeService timeService, ApprovalStore approvalStore) {
        this.timeService = timeService;
        this.approvalStore = approvalStore;
    }

    public void ensureRequiredApprovals(String userId,
                                        Collection<String> requestedScopes,
                                        String grantType,
                                        BaseClientDetails clientDetails) {
        Set<String> autoApprovedScopes = getAutoApprovedScopes(grantType, requestedScopes, clientDetails.getAutoApproveScopes());
        if(autoApprovedScopes.containsAll(requestedScopes)) { return; }
        Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);

        List<Approval> approvals = approvalStore.getApprovals(userId, clientDetails.getClientId(), IdentityZoneHolder.get().getId());
        for (Approval approval : approvals) {
            if (requestedScopes.contains(approval.getScope()) && approval.getStatus() == Approval.ApprovalStatus.APPROVED) {
                if (!approval.isActiveAsOf(timeService.getCurrentDate())) {
                    logger.debug("Approval " + approval + " has expired. Need to re-approve.");
                    throw new InvalidTokenException("Invalid token (approvals expired)");
                }
                approvedScopes.add(approval.getScope());
            }
        }

        if (!approvedScopes.containsAll(requestedScopes)) {
            logger.debug("All requested scopes " + requestedScopes + " were not approved. Approved scopes: " + approvedScopes);
            Set<String> unapprovedScopes = new HashSet<>(requestedScopes);
            unapprovedScopes.removeAll(approvedScopes);
            throw new InvalidTokenException("Invalid token (some requested scopes are not approved): "
                    + unapprovedScopes);
        }
    }

    private Set<String> getAutoApprovedScopes(Object grantType, Collection<String> tokenScopes, Set<String> autoapprovedScopes) {
        // ALL requested scopes are considered auto-approved for password grant
        if (grantType != null && GRANT_TYPE_PASSWORD.equals(grantType.toString())) {
            return new HashSet<>(tokenScopes);
        }
        return UaaTokenUtils.retainAutoApprovedScopes(tokenScopes, autoapprovedScopes);
    }
}
