
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class CompositeAuthenticationManager implements AuthenticationManager {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        OAuth2Authentication oauth2Authentication = null;
        if (a instanceof OAuth2Authentication) {
            oauth2Authentication = (OAuth2Authentication) a;
        }

        if (oauth2Authentication != null) {
            return oauth2Authentication.getUserAuthentication();
        }
        else {
            return authentication;
        }
    }
}
