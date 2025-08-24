package org.cloudfoundry.identity.uaa.oauth.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;

import java.io.Serial;
import java.util.Objects;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2Authentication extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 8200467823628026414L;

    private final OAuth2Request storedRequest;

    private final Authentication userAuthentication;

    /**
     * Construct an OAuth 2 authentication. Since some grant types don't require user authentication, the user
     * authentication may be null.
     * 
     * @param storedRequest The authorization request (must not be null).
     * @param userAuthentication The user authentication (possibly null).
     */
    public OAuth2Authentication(OAuth2Request storedRequest, Authentication userAuthentication) {
        super(userAuthentication == null ? storedRequest.getAuthorities() : userAuthentication.getAuthorities());
        this.storedRequest = storedRequest;
        this.userAuthentication = userAuthentication;
    }

    public Object getCredentials() {
        return "";
    }

    public Object getPrincipal() {
        return this.userAuthentication == null ? this.storedRequest.getClientId() : this.userAuthentication
                .getPrincipal();
    }

    /**
     * Convenience method to check if there is a user associated with this token, or just a client application.
     * 
     * @return true if this token represents a client app not acting on behalf of a user
     */
    public boolean isClientOnly() {
        return userAuthentication == null;
    }

    /**
     * The authorization request containing details of the client application.
     * 
     * @return The client authentication.
     */
    public OAuth2Request getOAuth2Request() {
        return storedRequest;
    }

    /**
     * The user authentication.
     * 
     * @return The user authentication.
     */
    public Authentication getUserAuthentication() {
        return userAuthentication;
    }

    @Override
    public boolean isAuthenticated() {
        return this.storedRequest.isApproved()
                && (this.userAuthentication == null || this.userAuthentication.isAuthenticated());
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        if (this.userAuthentication != null && CredentialsContainer.class.isAssignableFrom(this.userAuthentication.getClass())) {
            CredentialsContainer.class.cast(this.userAuthentication).eraseCredentials();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof OAuth2Authentication)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        OAuth2Authentication that = (OAuth2Authentication) o;
        if (!Objects.equals(storedRequest, that.storedRequest)) {
            return false;
        }
        if (!Objects.equals(userAuthentication, that.userAuthentication)) {
            return false;
        }
        return Objects.equals(getDetails(), that.getDetails());
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + storedRequest.hashCode();
        result = 31 * result + (userAuthentication != null ? userAuthentication.hashCode() : 0);
        return result;
    }

}
