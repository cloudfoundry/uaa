package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
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
    private final Log logger = LogFactory.getLog(getClass());

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

        // Search through the users approvals for scopes that are requested,
        // not auto approved, not expired, not DENIED and not approved more
        // recently than when this access token was issued.
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

        // Only issue the token if all the requested scopes have unexpired
        // approvals made before the refresh token was issued OR if those
        // scopes are auto approved
        if (!approvedScopes.containsAll(requestedScopes)) {
            logger.debug("All requested scopes " + requestedScopes + " were not approved " + approvedScopes);
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
