package org.cloudfoundry.identity.uaa.oauth.provider.approval;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class DefaultUserApprovalHandler implements UserApprovalHandler {

    private String approvalParameter = OAuth2Utils.USER_OAUTH_APPROVAL;

    /**
     * @param approvalParameter the approvalParameter to set
     */
    public void setApprovalParameter(String approvalParameter) {
        this.approvalParameter = approvalParameter;
    }

    /**
     * Basic implementation just requires the authorization request to be explicitly approved and the user to be
     * authenticated.
     * 
     * @param authorizationRequest The authorization request.
     * @param userAuthentication the current user authentication
     * 
     * @return Whether the specified request has been approved by the current user.
     */
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        return authorizationRequest.isApproved();
    }

    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        return authorizationRequest;
    }

    @Override
    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
        String flag = approvalParameters.get(approvalParameter);
        boolean approved = flag != null && "true".equalsIgnoreCase(flag);
        authorizationRequest.setApproved(approved);
        return authorizationRequest;
    }

    @Override
    public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
            Authentication userAuthentication) {
        Map<String, Object> model = new HashMap<>();
        // In case of a redirect we might want the request parameters to be included
        model.putAll(authorizationRequest.getRequestParameters());
        return model;
    }

}
