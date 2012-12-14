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

import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.codec.Hex;
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
	/**
	 * Dummy user allows the authentication process for non-existent and locked out users to be as close to
	 * that of normal users as possible to avoid differences in timing.
	 */
	private final UaaUser dummyUser;

	public AuthzAuthenticationManager(UaaUserDatabase cfusers) {
		this(cfusers, new BCryptPasswordEncoder());
	}

	public AuthzAuthenticationManager(UaaUserDatabase userDatabase, PasswordEncoder encoder) {
		this.userDatabase = userDatabase;
		this.encoder = encoder;
		this.dummyUser = createDummyUser();
	}

	@Override
	public Authentication authenticate(Authentication req) throws AuthenticationException {
		logger.debug("Processing authentication request for " + req.getName());

		if (req.getCredentials() == null) {
			BadCredentialsException e = new BadCredentialsException("No password supplied");
			publish(new AuthenticationFailureBadCredentialsEvent(req, e));
			throw e;
		}

		UaaUser user;
		try {
			user = userDatabase.retrieveUserByName(req.getName().toLowerCase(Locale.US));
		}
		catch (UsernameNotFoundException e) {
			user = dummyUser;
		}

		final boolean passwordMatches = encoder.matches((CharSequence) req.getCredentials(), user.getPassword());

		if (!accountLoginPolicy.isAllowed(user, req)) {
			logger.warn("Login policy rejected authentication for " + user.getUsername() + ", " + user.getId()
					+ ". Ignoring login request.");
			BadCredentialsException e = new BadCredentialsException("Login policy rejected authentication");
			publish(new AuthenticationFailureLockedEvent(req, e));
			throw e;
		}

		if (passwordMatches) {
			logger.debug("Password successfully matched");
			Authentication success = new UaaAuthentication(new UaaPrincipal(user),
						user.getAuthorities(), (UaaAuthenticationDetails) req.getDetails());
			publish(new UserAuthenticationSuccessEvent(user, success));

			return success;
		}

		if (user == dummyUser) {
			logger.debug("No user named '" + req.getName() + "' was found");
			publish(new UserNotFoundEvent(req));
		} else {
			logger.debug("Password did not match for user " + req.getName());
			publish(new UserAuthenticationFailureEvent(user, req));
		}
		BadCredentialsException e = new BadCredentialsException("Bad credentials");
		publish(new AuthenticationFailureBadCredentialsEvent(req, e));
		throw e;
	}
	
	private void publish(ApplicationEvent event) {
		if (eventPublisher!=null) {
			eventPublisher.publishEvent(event);
		}
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}

	public void setAccountLoginPolicy(AccountLoginPolicy accountLoginPolicy) {
		this.accountLoginPolicy = accountLoginPolicy;
	}

	private UaaUser createDummyUser() {
		// Create random unguessable password
		SecureRandom random = new SecureRandom();
		byte[] passBytes = new byte[16];
		random.nextBytes(passBytes);
		String password = encoder.encode(new String(Hex.encode(passBytes)));
		// Unique ID which isn't in the database
		final String id = UUID.randomUUID().toString();

		return new UaaUser("dummy_user", password, "dummy_user", "dummy", "dummy") {
			public final String getId() {
				return id;
			}

			public final List<? extends GrantedAuthority> getAuthorities() {
				throw new IllegalStateException();
			}
		};
	}
}
