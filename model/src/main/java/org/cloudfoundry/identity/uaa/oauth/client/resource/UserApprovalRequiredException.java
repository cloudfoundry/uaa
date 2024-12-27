package org.cloudfoundry.identity.uaa.oauth.client.resource;

import java.util.List;
import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
@SuppressWarnings("serial")
public class UserApprovalRequiredException extends RuntimeException {

    private final String approvalUri;

    private final Map<String, String> parameters;

    private final String clientId;

    private final List<String> scope;

    public UserApprovalRequiredException(String approvalUri, Map<String, String> parameters, String clientId, List<String> scope) {
        this.approvalUri = approvalUri;
        this.parameters = parameters;
        this.clientId = clientId;
        this.scope = scope;
    }

    /**
     * @return the approvalUri the uri to which the user should submit for approval
     */
    public String getApprovalUri() {
        return approvalUri;
    }

    /**
     * Description of the parameters required to be submitted for approval. Map from the name of the parameter to its
     * description.
     * 
     * @return the parameters the parameters required for approval
     */
    public Map<String, String> getParameters() {
        return parameters;
    }

    /**
     * @return the clientId the client that is requesting approval
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * @return the scope the scope that has been requested for the token grant
     */
    public List<String> getScope() {
        return scope;
    }

}
