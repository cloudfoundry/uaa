package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.UserApprovalHandler;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Component;

import java.util.*;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;

@Component("userManagedApprovalHandler")
public class UserManagedAuthzApprovalHandler implements UserApprovalHandler {

    private static final Logger logger = LoggerFactory.getLogger(UserManagedAuthzApprovalHandler.class);

    private static final String SCOPE_PREFIX = "scope.";

    private final ApprovalStore approvalStore;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final IdentityZoneManager identityZoneManager;
    private final int approvalExpiryInMillis;

    public UserManagedAuthzApprovalHandler(
            final @Qualifier("approvalStore") ApprovalStore approvalStore,
            final @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService,
            final @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager) {
        this.approvalStore = approvalStore;
        this.clientDetailsService = clientDetailsService;
        this.identityZoneManager = identityZoneManager;
        this.approvalExpiryInMillis = -1;
    }

    @Override
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {

        String approvalParameter1 = OAuth2Utils.USER_OAUTH_APPROVAL;
        String flag = authorizationRequest.getApprovalParameters().get(approvalParameter1);
        boolean userApproval = flag != null && "true".equalsIgnoreCase(flag);

        if (logger.isDebugEnabled()) {
            StringBuilder builder = new StringBuilder("Looking up user approved authorizations for ");
            builder.append("client_id=").append(authorizationRequest.getClientId());
            builder.append(" and username=").append(userAuthentication.getName());
            logger.debug(builder.toString());
        }

        Collection<String> requestedScopes = authorizationRequest.getScope();

        // Factor in auto approved scopes
        Set<String> autoApprovedScopes = new HashSet<>();
        UaaClientDetails client = (UaaClientDetails) clientDetailsService.retrieve(authorizationRequest.getClientId(), identityZoneManager.getCurrentIdentityZoneId());
        if (client != null && requestedScopes != null) {
            autoApprovedScopes.addAll(client.getAutoApproveScopes());
            autoApprovedScopes = UaaTokenUtils.retainAutoApprovedScopes(requestedScopes, autoApprovedScopes);
        }
        //translate scope to user scopes - including wild cards

        // TODO: the "true" case is not tested
        if (userApproval) {
            // Store the scopes that have been approved / denied
            Date expiry = computeExpiry();

            // Get the approved scopes, calculate the denied scope
            Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
            Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);
            boolean foundUserApprovalParameter = false;
            for (Map.Entry<String, String> entry : approvalParameters.entrySet()) {
                if (entry.getKey().startsWith(SCOPE_PREFIX)) {
                    approvedScopes.add(entry.getValue().substring(SCOPE_PREFIX.length()));
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
                        approvalStore.addApproval(approval, identityZoneManager.getCurrentIdentityZoneId());
                    } else {
                        Approval approval = new Approval()
                                .setUserId(getUserId(userAuthentication))
                                .setClientId(authorizationRequest.getClientId())
                                .setScope(requestedScope)
                                .setExpiresAt(expiry)
                                .setStatus(DENIED);
                        approvalStore.addApproval(approval, identityZoneManager.getCurrentIdentityZoneId());
                    }
                }

            } else { // Deny all except auto approved scopes
                authorizationRequest.setScope(autoApprovedScopes);

                for (String requestedScope : requestedScopes) {
                    if (!autoApprovedScopes.contains(requestedScope)) {
                        Approval approval = new Approval()
                                .setUserId(getUserId(userAuthentication))
                                .setClientId(authorizationRequest.getClientId())
                                .setScope(requestedScope)
                                .setExpiresAt(expiry)
                                .setStatus(DENIED);
                        approvalStore.addApproval(approval, identityZoneManager.getCurrentIdentityZoneId());
                    }
                }
            }

            return userAuthentication.isAuthenticated();

        } else {
            // Find the stored approvals for that user and client
            List<Approval> userApprovals = approvalStore.getApprovals(
                    getUserId(userAuthentication),
                    authorizationRequest.getClientId(),
                    identityZoneManager.getCurrentIdentityZoneId());

            // Look at the scopes and see if they have expired
            Set<String> approvedScopes = new HashSet<>(autoApprovedScopes);
            Set<String> validUserApprovedScopes = new HashSet<>(autoApprovedScopes);
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
                logger.debug("Valid user approved/denied scopes are {}", validUserApprovedScopes);
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
        } else {
            expiresAt.add(Calendar.MILLISECOND, approvalExpiryInMillis);
        }
        return expiresAt.getTime();
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
        return new HashMap<>(authorizationRequest.getRequestParameters());
    }
}
