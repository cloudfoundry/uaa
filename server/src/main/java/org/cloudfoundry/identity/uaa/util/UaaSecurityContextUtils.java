package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_AUTH_METHOD;

public final class UaaSecurityContextUtils {

    private UaaSecurityContextUtils() {
    }

    public static String getClientAuthenticationMethod() {
        return getClientAuthenticationMethod(SecurityContextHolder.getContext().getAuthentication());
    }

    public static String getClientAuthenticationMethod(Authentication a) {
        if (!(a instanceof OAuth2Authentication)) {
            if (a != null && a.isAuthenticated() && a.getDetails() instanceof UaaAuthenticationDetails) {
                return ((UaaAuthenticationDetails) a.getDetails()).getAuthenticationMethod();
            }
            return null;
        }
        OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) a;

        Map<String, Serializable> extensions = oAuth2Authentication.getOAuth2Request().getExtensions();
        if (extensions.isEmpty()) {
            return null;
        }

        return (String) extensions.get(CLIENT_AUTH_METHOD);
    }

}
