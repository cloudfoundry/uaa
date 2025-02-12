package org.cloudfoundry.identity.uaa.web;

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

import java.util.function.Supplier;

/**
 * Utility class for creating {@link AuthorizationManager} instances.
 */
public class AuthorizationManagersUtils {

    /**
     * Grants access if the user either anonymous, or fully authenticated.
     * <p>
     * Java equivalent of the SpEL expression {@code isAnonymous() or isFullyAuthenticated()}.
     */
    public static <T> AuthorizationManager<T> anonymousOrFullyAuthenticated() {
        return new AnoynmousOrFullyAuthenticated<T>();
    }

    private static class AnoynmousOrFullyAuthenticated<T> implements AuthorizationManager<T> {

        private final AuthenticatedAuthorizationManager<Object> anonymous
                = AuthenticatedAuthorizationManager.anonymous();
        private final AuthenticatedAuthorizationManager<Object> fullyAuthenticated
                = AuthenticatedAuthorizationManager.fullyAuthenticated();

        @Override
        public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
            var isAnonymous = anonymous.check(authentication, object);
            if (isAnonymous.isGranted()) { // NOSONAR
                return isAnonymous;
            }

            return fullyAuthenticated.check(authentication, object);
        }
    }
}
