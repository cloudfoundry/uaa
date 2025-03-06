package org.cloudfoundry.identity.uaa.web;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.cloudfoundry.identity.uaa.oauth.provider.expression.OAuth2ExpressionUtils;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2SecurityExpressionMethods;
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

    public static class AnyOfAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

        private final List<AuthorizationManager<RequestAuthorizationContext>> delegateAuthorizationManagers = new ArrayList<>();

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
            for (var authorizationManager : this.delegateAuthorizationManagers) {
                var decision = authorizationManager.check(authentication, object);
                if (decision != null && decision.isGranted()) {
                    return decision;
                }
            }
            return new AuthorizationDecision(false);
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
                    (auth, ctx) -> new AuthorizationDecision(OAuth2ExpressionUtils.hasAnyScope(auth.get(), scope))
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
                        return new AuthorizationDecision(securityMethods.hasScopeInAuthZone(scope));
                    }
            );
            return this;
        }
    }
}
