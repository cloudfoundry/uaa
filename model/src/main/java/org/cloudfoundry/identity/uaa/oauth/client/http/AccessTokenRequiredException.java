package org.cloudfoundry.identity.uaa.oauth.client.http;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * Moved class AccessTokenRequiredException implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class AccessTokenRequiredException extends InsufficientAuthenticationException {

    private final transient OAuth2ProtectedResourceDetails resource;

    public AccessTokenRequiredException(OAuth2ProtectedResourceDetails resource) {
        super("OAuth2 access denied.");
        this.resource = resource;
    }

    public AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource) {
        super(msg);
        this.resource = resource;
    }

    public AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
        super(msg, t);
        this.resource = resource;
    }

    public OAuth2ProtectedResourceDetails getResource() {
        return resource;
    }
}
