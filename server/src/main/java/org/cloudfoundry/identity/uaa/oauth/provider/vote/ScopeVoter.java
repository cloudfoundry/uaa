package org.cloudfoundry.identity.uaa.oauth.provider.vote;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server , validates scopes
 */
public class ScopeVoter implements AccessDecisionVoter<Object> {

    private String scopePrefix = "SCOPE_";

    private String denyAccess = "DENY_OAUTH";

    private boolean throwException = true;

    /**
     * Flag to determine the behaviour on access denied. If set then we throw an {@link InsufficientScopeException}
     * instead of returning {@link AccessDecisionVoter#ACCESS_DENIED}. This is unconventional for an access decision
     * voter because it vetos the other voters in the chain, but it enables us to pass a message to the caller with
     * information about the required scope.
     * 
     * @param throwException the flag to set (default true)
     */
    public void setThrowException(boolean throwException) {
        this.throwException = throwException;
    }

    /**
     * Allows the default role prefix of <code>SCOPE_</code> to be overridden. May be set to an empty value, although
     * this is usually not desirable.
     * 
     * @param scopePrefix the new prefix
     */
    public void setScopePrefix(String scopePrefix) {
        this.scopePrefix = scopePrefix;
    }

    /**
     * The name of the config attribute that can be used to deny access to OAuth2 client. Defaults to
     * <code>DENY_OAUTH</code>.
     * 
     * @param denyAccess the deny access attribute value to set
     */
    public void setDenyAccess(String denyAccess) {
        this.denyAccess = denyAccess;
    }

    public boolean supports(ConfigAttribute attribute) {
        return denyAccess.equals(attribute.getAttribute()) || (attribute.getAttribute() != null) && attribute.getAttribute().startsWith(scopePrefix);
    }

    /**
     * This implementation supports any type of class, because it does not query the presented secure object.
     * 
     * @param clazz the secure object
     * 
     * @return always <code>true</code>
     */
    public boolean supports(Class<?> clazz) {
        return true;
    }

    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        int result = ACCESS_ABSTAIN;

        if (!(authentication instanceof OAuth2Authentication)) {
            return result;

        }

        for (ConfigAttribute attribute : attributes) {
            if (denyAccess.equals(attribute.getAttribute())) {
                return ACCESS_DENIED;
            }
        }

        OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();

        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                result = ACCESS_DENIED;

                Set<String> scopes = clientAuthentication.getScope();
                for (String scope : scopes) {
                    if (attribute.getAttribute().equalsIgnoreCase((scopePrefix + scope))) {
                        return ACCESS_GRANTED;
                    }
                }
                if (throwException) {
                    InsufficientScopeException failure = new InsufficientScopeException(
                            "Insufficient scope for this resource", Collections.singleton(attribute.getAttribute()
                                    .substring(scopePrefix.length())));
                    throw new AccessDeniedException(failure.getMessage(), failure);
                }
            }
        }

        return result;
    }

}
