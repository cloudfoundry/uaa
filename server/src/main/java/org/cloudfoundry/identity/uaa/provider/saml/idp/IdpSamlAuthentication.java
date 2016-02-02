package org.cloudfoundry.identity.uaa.provider.saml.idp;

import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * This authentication object represents an SAML authentication requests that was authenticated using an openId login.
 * In other words, when the local SAML identity provider receives an authentication request from an external SAML
 * service provider, it authenticates the user using the UAA spring openId login page. UAA stores the result of that
 * authentication in an instance of this object. As such this object consists of a holder that contains both a
 * SamlAuthenticationToken, which provides the SAML context, and an OpenIdAuthenticationToken, which provides the
 * authentication details of the authenticated user.
 *
 */
public class IdpSamlAuthentication implements Authentication {

    /**
     * Generated serialization id.
     */
    private static final long serialVersionUID = -4895486519411522514L;

    private final IdpSamlCredentialsHolder credentials;

    public IdpSamlAuthentication(IdpSamlCredentialsHolder credentials) {
        this.credentials = credentials;
    }

    @Override
    public String getName() {
        return credentials.getLoginAuthenticationToken().getName();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return credentials.getLoginAuthenticationToken().getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getDetails() {
        return credentials.getLoginAuthenticationToken().getDetails();
    }

    @Override
    public Object getPrincipal() {
        return credentials.getLoginAuthenticationToken().getPrincipal();
    }

    @Override
    public boolean isAuthenticated() {
        return credentials.getLoginAuthenticationToken().isAuthenticated();
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        // Do nothing.
    }

    public static class IdpSamlCredentialsHolder {

        private final Authentication samlAuthenticationToken;
        private final Authentication loginAuthenticationToken;

        public IdpSamlCredentialsHolder(Authentication samlAuthenticationToken, Authentication loginAuthenticationToken) {
            this.samlAuthenticationToken = samlAuthenticationToken;
            this.loginAuthenticationToken = loginAuthenticationToken;
        }

        public Authentication getSamlAuthenticationToken() {
            return samlAuthenticationToken;
        }

        public Authentication getLoginAuthenticationToken() {
            return loginAuthenticationToken;
        }
    }
}
