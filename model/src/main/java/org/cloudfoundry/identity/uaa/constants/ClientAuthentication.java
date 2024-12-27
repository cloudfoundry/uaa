package org.cloudfoundry.identity.uaa.constants;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * ClientAuthentication constants are defined in OIDC core and discovery standard, e.g. https://openid.net/specs/openid-connect-registration-1_0.html
 * OIDC possible values are: client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt, and none
 * UAA knows only: client_secret_post, client_secret_basic, private_key_jwt, and none
 *
 * Planned: tls_client_auth
 */
public final class ClientAuthentication {

    private ClientAuthentication() {
    }

    public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    public static final String CLIENT_SECRET_POST = "client_secret_post";
    public static final String PRIVATE_KEY_JWT = "private_key_jwt";
    public static final String NONE = "none";

    public static final List<String> UAA_SUPPORTED_METHODS = List.of(CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, NONE, PRIVATE_KEY_JWT);

    public static boolean secretNeeded(String method) {
        return method == null || CLIENT_SECRET_POST.equals(method) || CLIENT_SECRET_BASIC.equals(method);
    }

    public static boolean isMethodSupported(String method) {
        return Optional.ofNullable(method).map(UAA_SUPPORTED_METHODS::contains).orElse(true);
    }

    public static boolean isValidMethod(String method, boolean hasSecret, boolean hasKeyConfiguration) {
        return isMethodSupported(method) && secretNeeded(method) && hasSecret && !hasKeyConfiguration ||
                isMethodSupported(method) && !secretNeeded(method) && !hasSecret ||
                (method == null && (!hasSecret || !hasKeyConfiguration));
    }

    public static boolean isAuthMethodEqual(String method1, String method2) {
        return secretNeeded(method1) && secretNeeded(method2) || Objects.equals(method1, method2);
    }

    public static String getCalculatedMethod(String method, boolean hasSecret, boolean hasKeyConfiguration) {
        if (method != null && isMethodSupported(method)) {
            return method;
        } else {
            if (hasSecret) {
                return CLIENT_SECRET_BASIC;
            } else if (hasKeyConfiguration) {
                return PRIVATE_KEY_JWT;
            } else {
                return NONE;
            }
        }
    }
}
