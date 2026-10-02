package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXTERNAL_ATTR;

public interface UaaTokenEnhancer {

    Map<String, String> getExternalAttributes(OAuth2Authentication authentication);

    /**
     * Names of claims, from those this enhancer returns, that are applied <em>after</em> UAA has set its own
     * defaults, so that the enhancer's value is the one that ends up in the access token.
     *
     * <p>Empty by default, which leaves an enhancer exactly as it has always been: its claims are applied before
     * UAA's defaults, and UAA's defaults take precedence for the claims UAA sets itself. This is an opt-in for an
     * enhancer that owns a claim UAA would otherwise overwrite (for example {@code sub} or {@code aud}); it does
     * not restrict, and is not needed by, any enhancer that does not.
     */
    default Set<String> getLateOverrideClaims() {
        return Set.of();
    }

    default Map<String, Object> enhance(Map<String, Object> claims, OAuth2Authentication authentication) {
        Map<String, Object> result = new HashMap<>();
        result.put(EXTERNAL_ATTR, getExternalAttributes(authentication));
        return result;
    }
}
