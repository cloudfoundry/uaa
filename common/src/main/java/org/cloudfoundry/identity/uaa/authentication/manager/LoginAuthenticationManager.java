package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class LoginAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

	private final Log logger = LogFactory.getLog(getClass());

	private ApplicationEventPublisher eventPublisher;

	private UaaUserDatabase userDatabase;

	boolean addNewAccounts = false;

	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	/**
	 * Flag to indicate that the scim user bootstrap (if provided) should be used to add new accounts when
	 * authenticated.
	 * 
	 * @param addNewAccounts the flag to set (default false)
	 */
	public void setAddNewAccounts(boolean addNewAccounts) {
		this.addNewAccounts = addNewAccounts;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}

	/**
	 * @param userDatabase the userDatabase to set
	 */
	public void setUserDatabase(UaaUserDatabase userDatabase) {
		this.userDatabase = userDatabase;
	}

	@Override
	public Authentication authenticate(Authentication request) throws AuthenticationException {

		if (!(request instanceof AuthzAuthenticationRequest)) {
			logger.debug("Cannot process request of type: " + request.getClass().getName());
			return null;
		}

		AuthzAuthenticationRequest req = (AuthzAuthenticationRequest) request;
		Map<String, String> info = req.getInfo();

		logger.debug("Processing authentication request for " + req.getName());

		SecurityContext context = SecurityContextHolder.getContext();

		if (context.getAuthentication() instanceof OAuth2Authentication) {
			OAuth2Authentication authentication = (OAuth2Authentication) context.getAuthentication();
			if (authentication.isClientOnly()) {
				UaaUser user = getUser(req, info);
				try {
					user = userDatabase.retrieveUserByName(user.getUsername());
				}
				catch (UsernameNotFoundException e) {
					// Not necessarily fatal
					if (addNewAccounts) {
						// Register new users automatically
						publish(new NewUserAuthenticatedEvent(user));
						try {
							user = userDatabase.retrieveUserByName(user.getUsername());
						}
						catch (UsernameNotFoundException ex) {
							throw new BadCredentialsException("Bad credentials");
						}
					}
					else {
						throw new BadCredentialsException("Bad credentials");
					}
				}
				Authentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(),
						(UaaAuthenticationDetails) req.getDetails());
				publish(new UserAuthenticationSuccessEvent(user, success));
				return success;
			}
		}

		logger.debug("Did not locate login credentials");
		return null;

	}

	protected void publish(ApplicationEvent event) {
		if (eventPublisher != null) {
			eventPublisher.publishEvent(event);
		}
	}

	protected UaaUser getUser(AuthzAuthenticationRequest req, Map<String, String> info) {
		String name = req.getName();
		String email = info.get("email");
		if (name == null && email != null) {
			name = email;
		}
		if (name == null) {
			throw new BadCredentialsException("Cannot determine username from credentials supplied");
		}
		if (email == null) {
			if (name.contains("@")) {
				email = name;
			}
			else {
				email = name + "@unknown.org";
			}
		}
		String givenName = info.get("given_name");
		if (givenName == null) {
			givenName = email.split("@")[0];
		}
		String familyName = info.get("family_name");
		if (familyName == null) {
			familyName = email.split("@")[1];
		}
		return new UaaUser(name, generator.generate(), email, givenName, familyName);
	}

}
