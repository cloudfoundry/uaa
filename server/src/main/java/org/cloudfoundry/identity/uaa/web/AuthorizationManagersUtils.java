package org.cloudfoundry.identity.uaa.web;

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

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
         * Grant access if the authentication is null or anonymous.
         */
        public AnyOfAuthorizationManager anonymous() {
            delegateAuthorizationManagers.add(AuthenticatedAuthorizationManager.anonymous());
            return this;
        }

        /**
         * Grant access if the authentication is authenticated and not remember-me.
         */
        public AnyOfAuthorizationManager fullyAuthenticated() {
            delegateAuthorizationManagers.add(AuthenticatedAuthorizationManager.fullyAuthenticated());
            return this;
        }

        /**
         * Grant access if the {@code authorizationManager} grants access.
         */
        public AnyOfAuthorizationManager or(AuthorizationManager<RequestAuthorizationContext> authorizationManager) {
            delegateAuthorizationManagers.add(authorizationManager);
            return this;
        }
    }
}
