package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Mutable, per-request context handed to each {@link IdTokenEnhancer}.
 *
 * <p>Carries the id_token claims assembled so far together with read-only access to the
 * inputs an enhancer may reason about: the {@link OAuth2Authentication} (possibly
 * {@code null} on the refresh flow), the claims of the access token issued in the same
 * response, and the claims of the refresh token issued in the same response.</p>
 *
 * <p>Not thread-safe; a new instance is created for every token request.</p>
 */
public class IdTokenEnhancementContext {

    private final Map<String, Object> claims;
    private final OAuth2Authentication authentication;
    private final Map<String, Object> accessTokenClaims;
    private final Map<String, Object> refreshTokenClaims;
    private final boolean allowClaimModification;
    private final Set<String> modifiedClaims = new LinkedHashSet<>();
    private final Set<String> rejectedClaimModifications = new LinkedHashSet<>();

    public IdTokenEnhancementContext(
            Map<String, Object> idTokenClaims,
            OAuth2Authentication authentication,
            Map<String, Object> accessTokenClaims,
            Map<String, Object> refreshTokenClaims,
            boolean allowClaimModification) {
        this.claims = new LinkedHashMap<>(idTokenClaims == null ? Collections.emptyMap() : idTokenClaims);
        this.authentication = authentication;
        this.accessTokenClaims = unmodifiableCopy(accessTokenClaims);
        this.refreshTokenClaims = unmodifiableCopy(refreshTokenClaims);
        this.allowClaimModification = allowClaimModification;
    }

    private static Map<String, Object> unmodifiableCopy(Map<String, Object> source) {
        return source == null
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }

    /**
     * Add or, when permitted, modify an id_token claim.
     *
     * <p>Adding a claim that is not yet present always succeeds. Replacing the value of a
     * claim that already exists (whether set by {@link IdTokenCreator} or by an earlier
     * enhancer) is only applied when claim modification has been explicitly enabled;
     * otherwise the original value is preserved and the attempt is recorded in
     * {@link #getRejectedClaimModifications()}.</p>
     *
     * @return {@code true} when the value was applied, {@code false} when it was refused
     */
    public boolean setClaim(String name, Object value) {
        Objects.requireNonNull(name, "claim name must not be null");
        if (!claims.containsKey(name)) {
            claims.put(name, value);
            return true;
        }
        if (allowClaimModification) {
            claims.put(name, value);
            modifiedClaims.add(name);
            return true;
        }
        rejectedClaimModifications.add(name);
        return false;
    }

    public Object getClaim(String name) {
        return claims.get(name);
    }

    public boolean hasClaim(String name) {
        return claims.containsKey(name);
    }

    public OAuth2Authentication getAuthentication() {
        return authentication;
    }

    public Map<String, Object> getAccessTokenClaims() {
        return accessTokenClaims;
    }

    public Object getAccessTokenClaim(String name) {
        return accessTokenClaims.get(name);
    }

    public Map<String, Object> getRefreshTokenClaims() {
        return refreshTokenClaims;
    }

    public Object getRefreshTokenClaim(String name) {
        return refreshTokenClaims.get(name);
    }

    public boolean isClaimModificationAllowed() {
        return allowClaimModification;
    }

    /**
     * @return a snapshot copy of the id_token claims accumulated so far; safe to hand out
     */
    public Map<String, Object> getClaims() {
        return new LinkedHashMap<>(claims);
    }

    public Set<String> getModifiedClaims() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(modifiedClaims));
    }

    public Set<String> getRejectedClaimModifications() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(rejectedClaimModifications));
    }
}
