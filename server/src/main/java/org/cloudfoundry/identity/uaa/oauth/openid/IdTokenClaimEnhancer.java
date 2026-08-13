package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.List;
import java.util.Map;

/**
 * Applies the configured {@link IdTokenEnhancer}s to an id_token's claims.
 *
 * <p>Skeleton implementation: every method throws until the behaviour is implemented.</p>
 */
public class IdTokenClaimEnhancer {

    public IdTokenClaimEnhancer(
            List<IdTokenEnhancer> enhancers,
            boolean allowClaimModification,
            Map<String, Object> properties) {
        throw new UnsupportedOperationException("IdTokenClaimEnhancer is not implemented yet");
    }

    public static IdTokenClaimEnhancer noOp() {
        throw new UnsupportedOperationException("not implemented");
    }

    public boolean isClaimModificationAllowed() {
        throw new UnsupportedOperationException("not implemented");
    }

    public Map<String, Object> enhance(
            Map<String, Object> idTokenClaims,
            OAuth2Authentication authentication,
            Map<String, Object> accessTokenClaims,
            Map<String, Object> refreshTokenClaims) {
        throw new UnsupportedOperationException("not implemented");
    }
}
