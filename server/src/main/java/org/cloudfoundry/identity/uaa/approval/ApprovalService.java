package org.cloudfoundry.identity.uaa.approval;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;

@RequiredArgsConstructor
@Slf4j
public class ApprovalService {
    private final TimeService timeService;
    private final ApprovalStore approvalStore;
    private final IdentityZoneManager identityZoneManager;

    public void ensureRequiredApprovals(String userId,
            Collection<String> requestedScopes,
            String grantType,
            UaaClientDetails clientDetails) {
        Set<String> autoApprovedScopes = getAutoApprovedScopes(grantType, requestedScopes, clientDetails.getAutoApproveScopes());
        if (autoApprovedScopes.containsAll(requestedScopes)) {
            return;
        }
        Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);

        List<Approval> approvals = approvalStore.getApprovals(userId, clientDetails.getClientId(), identityZoneManager.getCurrentIdentityZoneId());
        for (Approval approval : approvals) {
            if (requestedScopes.contains(approval.getScope()) && approval.getStatus() == Approval.ApprovalStatus.APPROVED) {
                if (!approval.isActiveAsOf(timeService.getCurrentDate())) {
                    log.debug("Approval {} has expired. Need to re-approve.", approval);
                    throw new InvalidTokenException("Invalid token (approvals expired)");
                }
                approvedScopes.add(approval.getScope());
            }
        }

        if (!approvedScopes.containsAll(requestedScopes)) {
            log.debug("All requested scopes {} were not approved. Approved scopes: {}", requestedScopes, approvedScopes);
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
