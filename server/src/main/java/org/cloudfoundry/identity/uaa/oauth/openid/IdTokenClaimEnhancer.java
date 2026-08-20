package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Applies the configured {@link IdTokenEnhancer}s to an id_token's claims.
 *
 * <p>Holds the ordered list of enhancers and the operator-controlled
 * {@code allowClaimModification} switch (default {@code false}). A single instance is
 * shared across all token requests; a fresh {@link IdTokenEnhancementContext} is created
 * per {@link #enhance} call.</p>
 */
public class IdTokenClaimEnhancer {

    private final List<IdTokenEnhancer> enhancers;
    private final boolean allowClaimModification;

    public IdTokenClaimEnhancer(
            List<IdTokenEnhancer> enhancers,
            boolean allowClaimModification) {
        this.enhancers = enhancers == null ? Collections.emptyList() : List.copyOf(enhancers);
        this.allowClaimModification = allowClaimModification;
    }

    /**
     * @return an enhancer that makes no changes and imposes no per-request cost
     */
    public static IdTokenClaimEnhancer noOp() {
        return new IdTokenClaimEnhancer(Collections.emptyList(), false);
    }

    public boolean isClaimModificationAllowed() {
        return allowClaimModification;
    }

    /**
     * Run every configured enhancer against the given id_token claims.
     *
     * <p>When no enhancers are configured the supplied map is returned unchanged and
     * un-copied, so the default issuance path is unaffected. Otherwise the enhancers
     * operate on a private copy and the resulting claim map is returned; the
     * {@code idTokenClaims} argument is never mutated.</p>
     *
     * @param idTokenClaims      the standard claims assembled by {@link IdTokenCreator}
     * @param authentication     the current authentication, or {@code null} (e.g. refresh flow)
     * @param accessTokenClaims  claims of the access token issued in the same response
     * @param refreshTokenClaims claims of the refresh token issued in the same response, or
     *                           empty when no refresh token was issued
     * @return the (possibly enhanced) id_token claims to be signed
     */
    public Map<String, Object> enhance(
            Map<String, Object> idTokenClaims,
            OAuth2Authentication authentication,
            Map<String, Object> accessTokenClaims,
            Map<String, Object> refreshTokenClaims) {
        if (enhancers.isEmpty()) {
            return idTokenClaims;
        }
        IdTokenEnhancementContext context = new IdTokenEnhancementContext(
                idTokenClaims,
                authentication,
                accessTokenClaims,
                refreshTokenClaims,
                allowClaimModification);
        for (IdTokenEnhancer enhancer : enhancers) {
            enhancer.enhance(context);
        }
        return context.getClaims();
    }
}
