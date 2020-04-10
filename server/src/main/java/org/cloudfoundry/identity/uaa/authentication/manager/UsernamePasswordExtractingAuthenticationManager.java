

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Authentication filter translating a generic Authentication into a
 * UsernamePasswordAuthenticationToken.
 * 
 * @author Dave Syer
 * 
 */
public class UsernamePasswordExtractingAuthenticationManager implements AuthenticationManager {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final AuthenticationManager delegate;

    /**
     * @param delegate
     */
    public UsernamePasswordExtractingAuthenticationManager(AuthenticationManager delegate) {
        super();
        this.delegate = delegate;
    }

    /*
     * (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationManager#
     * authenticate(org.springframework.security.core.Authentication)
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication == null) {
            return authentication;
        }
        UsernamePasswordAuthenticationToken output = null;
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            output = (UsernamePasswordAuthenticationToken) authentication;
        } else {
            output = new UsernamePasswordAuthenticationToken(authentication, authentication.getCredentials(),
                            authentication.getAuthorities());
            output.setAuthenticated(authentication.isAuthenticated());
            output.setDetails(authentication.getDetails());
        }
        return delegate.authenticate(output);
    }

}
