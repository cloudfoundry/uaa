package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.provider.saml.idp.IdpSamlAuthentication.IdpSamlCredentialsHolder;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLAuthenticationToken;

/**
 * This authentication provider produces a composite authentication object that contains the SamlAuthenticationToken,
 * which contains the SAML context, and the OpenIdAuthenticationToken, which contains information about the
 * authenticated user.
 */
public class IdpSamlAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication loginAuthenticationToken = securityContext.getAuthentication();

        IdpSamlCredentialsHolder credentials = new IdpSamlCredentialsHolder(authentication, loginAuthenticationToken);

        return new IdpSamlAuthentication(credentials);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SAMLAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
