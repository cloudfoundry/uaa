package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 */
public class AuthzAuthenticationMgr implements AuthenticationManager {
	private final Log logger = LogFactory.getLog(getClass());
	private final PasswordEncoder encoder;
	private final UaaUserService cfusers;

	public AuthzAuthenticationMgr(UaaUserService cfusers) {
		this(cfusers, NoOpPasswordEncoder.getInstance());
	}

	public AuthzAuthenticationMgr(UaaUserService cfusers, PasswordEncoder encoder) {
		this.cfusers = cfusers;
		this.encoder = encoder;
	}

	@Override
	public Authentication authenticate(Authentication req) throws AuthenticationException {
		try {
			UaaUser user = cfusers.getUser(req.getName());

			if (encoder.matches((CharSequence) req.getCredentials(), user.getPassword())) {
				return new UaaAuthentication(cfusers.getPrincipal(user), user.getAuthorities());
			}
			throw new BadCredentialsException("Bad credentials");
		}
		catch (UsernameNotFoundException e) {
			logger.debug("No user named '" + req.getName() + "' was found");
			throw new BadCredentialsException("Bad credentials");
		}
	}
}
