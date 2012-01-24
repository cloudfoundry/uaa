/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.Locale;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author Luke Taylor
 * @author Dave Syer
 *
 */
public class AuthzAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

	private final Log logger = LogFactory.getLog(getClass());
	private final PasswordEncoder encoder;
	private final UaaUserDatabase userDatabase;
	private ApplicationEventPublisher eventPublisher;

	public AuthzAuthenticationManager(UaaUserDatabase cfusers) {
		this(cfusers, new BCryptPasswordEncoder());
	}

	public AuthzAuthenticationManager(UaaUserDatabase userDatabase, PasswordEncoder encoder) {
		this.userDatabase = userDatabase;
		this.encoder = encoder;
	}

	@Override
	public Authentication authenticate(Authentication req) throws AuthenticationException {
		try {
			logger.debug("Processing authentication request for " + req.getName());
			UaaUser user = userDatabase.retrieveUserByName(req.getName().toLowerCase(Locale.US));

			if (encoder.matches((CharSequence) req.getCredentials(), user.getPassword())) {
				logger.debug("Password successfully matched");
				Authentication success = new UaaAuthentication(new UaaPrincipal(user),
							user.getAuthorities(), (UaaAuthenticationDetails) req.getDetails());
				eventPublisher.publishEvent(new UserAuthenticationSuccessEvent(user, success));

				return success;
			}
			logger.debug("Password did not match");
			eventPublisher.publishEvent(new UserAuthenticationFailureEvent(user, req));

			throw new BadCredentialsException("Bad credentials");
		}
		catch (UsernameNotFoundException e) {
			eventPublisher.publishEvent(new UserNotFoundEvent(req));
			logger.debug("No user named '" + req.getName() + "' was found");
			throw new BadCredentialsException("Bad credentials");
		}
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}
}
