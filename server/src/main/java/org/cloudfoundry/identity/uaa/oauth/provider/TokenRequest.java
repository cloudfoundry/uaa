package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class TokenRequest extends BaseRequest {

    private String grantType;
    private TokenActor tokenActor;

    /**
     * Default constructor
     */
    protected TokenRequest() {
    }

    /**
     * Full constructor. Sets this TokenRequest's requestParameters map to an unmodifiable version of the one provided.
     *
     * @param requestParameters
     * @param clientId
     * @param scope
     * @param grantType
     */
    public TokenRequest(Map<String, String> requestParameters, String clientId, Collection<String> scope,
            String grantType) {
        setClientId(clientId);
        setRequestParameters(requestParameters);
        setScope(scope);
        this.grantType = grantType;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    @Override
    public void setClientId(String clientId) {
        super.setClientId(clientId);
    }

    /**
     * Set the scope value. If the collection contains only a single scope value, this method will parse that value into
     * a collection using {@link OAuth2Utils#parseParameterList}.
     *
     * @see AuthorizationRequest#setScope
     *
     * @param scope
     */
    @Override
    public void setScope(Collection<String> scope) {
        super.setScope(scope);
    }

    /**
     * Set the Request Parameters on this authorization request, which represent the original request parameters and
     * should never be changed during processing. The map passed in is wrapped in an unmodifiable map instance.
     *
     * @see AuthorizationRequest#setRequestParameters
     *
     * @param requestParameters
     */
    @Override
    public void setRequestParameters(Map<String, String> requestParameters) {
        super.setRequestParameters(requestParameters);
    }

    public OAuth2Request createOAuth2Request(ClientDetails client) {
        Map<String, String> requestParameters = getRequestParameters();
        HashMap<String, String> modifiable = new HashMap<>(requestParameters);
        // Remove password if present to prevent leaks
        modifiable.remove("password");
        modifiable.remove("client_secret");
        // Add grant type so it can be retrieved from OAuth2Request
        modifiable.put(OAuth2Utils.GRANT_TYPE, grantType);
        return new OAuth2Request(modifiable, client.getClientId(), client.getAuthorities(), true, this.getScope(),
                client.getResourceIds(), null, null, null, getTokenActor());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        if (!super.equals(obj)) {
            return false;
        }
        TokenRequest other = (TokenRequest) obj;
        return Objects.equals(grantType, other.grantType);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (grantType != null ? grantType.hashCode() : 0);
        return result;
    }

    public TokenActor getTokenActor() {
        return tokenActor;
    }

    public void setTokenActor(TokenActor tokenActor) {
        this.tokenActor = tokenActor;
    }
}
