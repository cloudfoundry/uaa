package org.cloudfoundry.identity.uaa.web;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2ExpressionUtils;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2SecurityExpressionMethods;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Utility class for creating {@link AuthorizationManager} instances.
 */
public class AuthorizationManagersUtils {

    /**
     * Grants access if any of the registered authorization managers grants access.
     */
    public static AnyOfAuthorizationManager anyOf() {
        return new AnyOfAuthorizationManager();
    }

    public static AnyOfAuthorizationManager anyOf(boolean throwOnMissingScope) {
        AnyOfAuthorizationManager result = anyOf();
        if (throwOnMissingScope) {
            result.throwOnMissingScope();
        }
        return result;
    }

    public static class AnyOfAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

        private final List<AuthorizationManager<RequestAuthorizationContext>> delegateAuthorizationManagers = new ArrayList<>();
        private boolean throwOnMissingScope = false;
        private Set<String> missingScopes = new LinkedHashSet<>();

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
            for (var authorizationManager : this.delegateAuthorizationManagers) {
                AuthorizationDecision decision = authorizationManager.check(authentication, object);
                if (decision != null) {
                    if (decision.isGranted()) {
                        return decision;
                    } else if (decision instanceof ScopeTrackingAuthorizationDecision scopeDecision) {
                        missingScopes.addAll(scopeDecision.getScopes());
                    }
                }

            }
            if (throwOnMissingScope && !missingScopes.isEmpty()) {
                Throwable failure = new InsufficientScopeException("Insufficient scope for this resource", missingScopes);
                throw new AccessDeniedException(failure.getMessage(), failure);
            }
            return new AuthorizationDecision(false);
        }

        public AnyOfAuthorizationManager throwOnMissingScope() {
            this.throwOnMissingScope = true;
            return this;
        }

        /**
         * Grants access if the authentication is null or anonymous.
         */
        public AnyOfAuthorizationManager anonymous() {
            delegateAuthorizationManagers.add(AuthenticatedAuthorizationManager.anonymous());
            return this;
        }

        /**
         * Grants access if the authentication is authenticated and not remember-me.
         */
        public AnyOfAuthorizationManager fullyAuthenticated() {
            delegateAuthorizationManagers.add(AuthenticatedAuthorizationManager.fullyAuthenticated());
            return this;
        }

        /**
         * Grants access if the {@code authorizationManager} grants access.
         */
        public AnyOfAuthorizationManager or(AuthorizationManager<RequestAuthorizationContext> authorizationManager) {
            delegateAuthorizationManagers.add(authorizationManager);
            return this;
        }

        /**
         * Grants access to UAA admins.
         */
        public AnyOfAuthorizationManager isUaaAdmin() {
            return hasScope("uaa.admin");
        }

        /**
         * Is zone administrator of the current IdentityZone.
         */
        public AnyOfAuthorizationManager isZoneAdmin() {
            return hasScopeWithZoneId("zones.{zone.id}.admin");
        }

        /**
         * Grants access for the given scope.
         *
         * @deprecated Upgrade in 3.x
         */
        public AnyOfAuthorizationManager hasScope(String... scope) {
            delegateAuthorizationManagers.add(
                    (auth, ctx) -> new ScopeTrackingAuthorizationDecision(OAuth2ExpressionUtils.hasAnyScope(auth.get(), scope), scope)
            );
            return this;
        }

        /**
         * Grants access for the given scope, swapping {@code {zone.id}} for the current Zone ID.
         */
        public AnyOfAuthorizationManager hasScopeWithZoneId(String scope) {
            delegateAuthorizationManagers.add(
                    (auth, ctx) -> {
                        var securityMethods = new ContextSensitiveOAuth2SecurityExpressionMethods(auth.get());
                        return new ScopeTrackingAuthorizationDecision(securityMethods.hasScopeInAuthZone(scope), scope);
                    }
            );
            return this;
        }
    }

    private static class ScopeTrackingAuthorizationDecision extends AuthorizationDecision {
        private Set<String> scopes = new LinkedHashSet<>();
        public ScopeTrackingAuthorizationDecision(boolean granted, String... scopes) {
            super(granted);
            if (scopes != null) {
                Collections.addAll(this.scopes, scopes);
            }
        }

        public Set<String> getScopes() {
            return this.scopes;
        }
    }
}
