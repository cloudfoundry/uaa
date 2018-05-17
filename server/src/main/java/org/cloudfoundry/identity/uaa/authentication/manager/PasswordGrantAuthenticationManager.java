package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class PasswordGrantAuthenticationManager implements AuthenticationManager {

    private DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;

    public PasswordGrantAuthenticationManager(DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager) {
        this.zoneAwareAuthzAuthenticationManager = zoneAwareAuthzAuthenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UaaLoginHint uaaLoginHint = zoneAwareAuthzAuthenticationManager.extractLoginHint(authentication);
        if (uaaLoginHint == null || uaaLoginHint.getOrigin() == null || uaaLoginHint.getOrigin().equals(OriginKeys.UAA) || uaaLoginHint.getOrigin().equals(OriginKeys.LDAP)) {
            return zoneAwareAuthzAuthenticationManager.authenticate(authentication);
        }
        return null;
    }
}
