package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.UserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class UaaUserApprovalHandler implements UserApprovalHandler {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final MultitenantClientServices clientDetailsService;
    private final OAuth2RequestFactory requestFactory;
    private final AuthorizationServerTokenServices tokenServices;
    private final IdentityZoneManager identityZoneManager;

    public UaaUserApprovalHandler(
            final MultitenantClientServices clientDetailsService,
            final OAuth2RequestFactory requestFactory,
            final AuthorizationServerTokenServices tokenServices,
            final IdentityZoneManager identityZoneManager) {
        this.clientDetailsService = clientDetailsService;
        this.requestFactory = requestFactory;
        this.tokenServices = tokenServices;
        this.identityZoneManager = identityZoneManager;
    }

    /**
     * Allows automatic approval for a white list of clients in the implicit
     * grant case.
     *
     * @param authorizationRequest The authorization request.
     * @param userAuthentication   the current user authentication
     * @return Whether the specified request has been approved by the current
     * user.
     */
    @Override
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        if (!userAuthentication.isAuthenticated()) {
            return false;
        }
        if (authorizationRequest.isApproved()) {
            return true;
        }
        final ClientDetails client = clientDetailsService.loadClientByClientId(
                authorizationRequest.getClientId(),
                identityZoneManager.getCurrentIdentityZoneId());
        final Collection<String> requestedScopes = authorizationRequest.getScope();
        return isAutoApprove(client, requestedScopes);
    }

    private boolean isAutoApprove(ClientDetails client, Collection<String> scopes) {
        UaaClientDetails baseClient = (UaaClientDetails) client;

        if (baseClient.getAutoApproveScopes() == null) {
            return false;
        }

        if (baseClient.getAutoApproveScopes().contains("true")) {
            return true;
        }

        return baseClient.getAutoApproveScopes().containsAll(scopes);
    }

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        boolean approved = false;

        String clientId = authorizationRequest.getClientId();
        Set<String> scopes = authorizationRequest.getScope();
        try {
            ClientDetails client = clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
            approved = true;
            for (String scope : scopes) {
                if (!client.isAutoApprove(scope)) {
                    approved = false;
                }
            }
            if (approved) {
                authorizationRequest.setApproved(true);
                return authorizationRequest;
            }
        } catch (ClientRegistrationException e) {
            logger.warn("Client registration problem prevent autoapproval check for client={}", clientId);
        }

        OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(authorizationRequest);

        OAuth2Authentication authentication = new OAuth2Authentication(storedOAuth2Request, userAuthentication);
        if (logger.isDebugEnabled()) {
            final String logMessage = "Looking up existing token for client_id=%s, scope=%s and username=%s".formatted(
                    clientId,
                    scopes,
                    userAuthentication.getName());
            logger.debug(logMessage);
        }

        OAuth2AccessToken accessToken = tokenServices.getAccessToken(authentication);
        logger.debug("Existing access token={}", accessToken);
        if (accessToken != null && !accessToken.isExpired()) {
            logger.debug("User already approved with token={}", accessToken);
            // A token was already granted and is still valid, so this is already approved
            approved = true;
        } else {
            logger.debug("Checking explicit approval");
            approved = userAuthentication.isAuthenticated() && approved;
        }

        authorizationRequest.setApproved(approved);

        return authorizationRequest;
    }

    @Override
    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
        String flag = approvalParameters.get(OAuth2Utils.USER_OAUTH_APPROVAL);
        boolean approved = flag != null && "true".equalsIgnoreCase(flag);
        authorizationRequest.setApproved(approved);
        return authorizationRequest;
    }

    @Override
    public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
            Authentication userAuthentication) {
        // In case of a redirect we might want the request parameters to be included
        return new HashMap<>(authorizationRequest.getRequestParameters());
    }
}
