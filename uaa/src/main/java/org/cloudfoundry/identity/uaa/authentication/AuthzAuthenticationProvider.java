package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 */
public class AuthzAuthenticationProvider implements AuthenticationProvider {
	private final Log logger = LogFactory.getLog(getClass());
	private final PasswordEncoder encoder;
	private final UaaUserService cfusers;

	public AuthzAuthenticationProvider(UaaUserService cfusers) {
		this(cfusers, NoOpPasswordEncoder.getInstance());
	}

	public AuthzAuthenticationProvider(UaaUserService cfusers, PasswordEncoder encoder) {
		this.cfusers = cfusers;
		this.encoder = encoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthzAuthenticationRequest req = (AuthzAuthenticationRequest) authentication;

		try {
			UaaUser user = cfusers.getUser(req.getName());

			if (encoder.matches(req.getCredentials(), user.getPassword())) {
				// TODO: insert OTP check here
				return new UaaAuthentication(cfusers.getPrincipal(user), user.getAuthorities());
			}
			throw new BadCredentialsException("Bad credentials");
		}
		catch (UsernameNotFoundException e) {
			logger.debug("No user named '" + req.getName() + "' was found");
			throw new BadCredentialsException("Bad credentials");
		}
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return clazz.isAssignableFrom(AuthzAuthenticationRequest.class);
	}
}
