package org.cloudfoundry.identity.uaa.oauth.openid;

/**
 * Extension point for contributing or adjusting claims on the OpenID Connect
 * {@code id_token} that UAA issues.
 *
 * <p>This is the id_token counterpart to
 * {@link org.cloudfoundry.identity.uaa.oauth.UaaTokenEnhancer}, which only affects the
 * access and refresh tokens. Implementations are invoked once per id_token, after
 * {@link IdTokenCreator} has assembled the standard claim set and immediately before the
 * token is signed.</p>
 *
 * <p>Through the supplied {@link IdTokenEnhancementContext} an implementation may:</p>
 * <ul>
 *   <li>read UAA configuration properties exposed to enhancers,</li>
 *   <li>read the current {@link org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication},</li>
 *   <li>read the claims of the access token issued in the same response,</li>
 *   <li>read the additional root claims associated with the refresh token, and</li>
 *   <li>add new claims to the id_token.</li>
 * </ul>
 *
 * <p>Adding a claim that is not already present always succeeds. Overwriting a claim that
 * {@link IdTokenCreator} (or an earlier enhancer) already set is refused unless the operator
 * has explicitly opted in via {@code jwt.token.idToken.enhancer.allowClaimModification}
 * (default {@code false}); see {@link IdTokenEnhancementContext#setClaim(String, Object)}.</p>
 *
 * <p>Implementations must be thread-safe: a single instance is shared across all token
 * requests. They must also tolerate a {@code null} authentication, which occurs on the
 * refresh-token flow where no live authentication object exists.</p>
 */
@FunctionalInterface
public interface IdTokenEnhancer {

    /**
     * Contribute to or adjust the id_token claims held by the given context.
     *
     * @param context mutable per-request enhancement context; never {@code null}
     */
    void enhance(IdTokenEnhancementContext context);
}
