package org.cloudfoundry.identity.uaa.oauth.client.resource;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2
 */
@SuppressWarnings("serial")
public class OAuth2AccessDeniedException extends OAuth2Exception {

    private final transient OAuth2ProtectedResourceDetails resource;

    public OAuth2AccessDeniedException() {
        this("OAuth2 access denied.");
    }

    public OAuth2AccessDeniedException(String msg) {
        super(msg);
        resource = null;
    }

    public OAuth2AccessDeniedException(OAuth2ProtectedResourceDetails resource) {
        super("OAuth2 access denied.");
        this.resource = resource;
    }

    public OAuth2AccessDeniedException(String msg, OAuth2ProtectedResourceDetails resource) {
        super(msg);
        this.resource = resource;
    }

    public OAuth2AccessDeniedException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
        super(msg, t);
        this.resource = resource;
    }

    public OAuth2ProtectedResourceDetails getResource() {
        return resource;
    }

    @Override
    public String getOAuth2ErrorCode() {
        return "access_denied";
    }

    @Override
    public int getHttpErrorCode() {
        return 403;
    }
}
