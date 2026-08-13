package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.Map;
import java.util.Set;

/**
 * Mutable, per-request context handed to each {@link IdTokenEnhancer}.
 *
 * <p>Skeleton implementation: every method throws until the behaviour is implemented.
 * The accompanying tests therefore fail on this commit and pass once the implementation
 * commit lands.</p>
 */
public class IdTokenEnhancementContext {

    public IdTokenEnhancementContext(
            Map<String, Object> idTokenClaims,
            OAuth2Authentication authentication,
            Map<String, Object> accessTokenClaims,
            Map<String, Object> refreshTokenClaims,
            Map<String, Object> properties,
            boolean allowClaimModification) {
        throw new UnsupportedOperationException("IdTokenEnhancementContext is not implemented yet");
    }

    public boolean setClaim(String name, Object value) {
        throw new UnsupportedOperationException("not implemented");
    }

    public Object getClaim(String name) {
        throw new UnsupportedOperationException("not implemented");
    }

    public boolean hasClaim(String name) {
        throw new UnsupportedOperationException("not implemented");
    }

    public OAuth2Authentication getAuthentication() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Map<String, Object> getAccessTokenClaims() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Object getAccessTokenClaim(String name) {
        throw new UnsupportedOperationException("not implemented");
    }

    public Map<String, Object> getRefreshTokenClaims() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Object getRefreshTokenClaim(String name) {
        throw new UnsupportedOperationException("not implemented");
    }

    public Map<String, Object> getProperties() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Object getProperty(String name) {
        throw new UnsupportedOperationException("not implemented");
    }

    public boolean isClaimModificationAllowed() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Map<String, Object> getClaims() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Set<String> getModifiedClaims() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Set<String> getRejectedClaimModifications() {
        throw new UnsupportedOperationException("not implemented");
    }
}
