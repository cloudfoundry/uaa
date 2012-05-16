/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
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
	private AccountLoginPolicy accountLoginPolicy = new PermitAllAccountLoginPolicy();

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

			if (!accountLoginPolicy.isAllowed(user, req)) {
				logger.warn("Login policy rejected authentication for " + user.getUsername() + ", " + user.getId()
						+ ". Ignoring login request.");
				// TODO: We should perhaps have another audit event type here
				// since this will not be logged as an authentication failure.
				throw new BadCredentialsException("Login policy rejected authentication");
			}

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

	public void setAccountLoginPolicy(AccountLoginPolicy accountLoginPolicy) {
		this.accountLoginPolicy = accountLoginPolicy;
	}
}
