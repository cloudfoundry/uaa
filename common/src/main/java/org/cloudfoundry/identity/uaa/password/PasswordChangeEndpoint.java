package org.cloudfoundry.identity.uaa.password;

import java.security.Principal;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.event.NoUserPasswordFailureEvent;
import org.cloudfoundry.identity.uaa.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.event.PasswordFailureEvent;
import org.cloudfoundry.identity.uaa.rest.SimpleMessage;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Email;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConstraintFailedException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

@Controller
public class PasswordChangeEndpoint implements ApplicationEventPublisherAware {

	private final Log logger = LogFactory.getLog(getClass());

	private ScimUserProvisioning dao;

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	private ApplicationEventPublisher publisher;

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
			new HttpMessageConverter<?>[0]);

	public PasswordChangeEndpoint(ScimUserProvisioning provisioning) {
		this.dao = provisioning;
	}

	/**
	 * Set the message body converters to use.
	 * <p>
	 * These converters are used to convert from and to HTTP requests and responses.
	 */
	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
		this.publisher = publisher;
	}

	void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	@RequestMapping(value = "/Users/{userId}/password", method = RequestMethod.PUT)
	@ResponseBody
	public SimpleMessage changePassword(@PathVariable String userId, @RequestBody PasswordChangeRequest change,
			Principal principal, @RequestParam(required = false, defaultValue = "true") boolean lookup) {
		UaaUser user = getUser(userId, lookup);
		try {
			checkPasswordChangeIsAllowed(userId, change.getOldPassword());
		}
		catch (InvalidPasswordException e) {
			publish(new PasswordFailureEvent(e.getMessage(), user, principal));
			throw e;
		}
		if (!dao.changePassword(userId, change.getOldPassword(), change.getPassword())) {
			publish(new PasswordFailureEvent("Password not changed", user, principal));
			throw new InvalidPasswordException("Password not changed for user: " + userId);
		}
		publish(new PasswordChangeEvent("Password updated", user, principal));
		return new SimpleMessage("ok", "password updated");
	}

	private void publish(AbstractUaaEvent event) {
		if (publisher != null) {
			publisher.publishEvent(event);
		}
	}

	private UaaUser getUser(String userId, boolean lookup) {
		try {
			if (dao != null) {
				// If the request came in for a user by id we should be able to retrieve the username
				ScimUser scimUser = dao.retrieveUser(userId);
				if (scimUser != null) {
					return new UaaUser(scimUser.getUserName(), "N/A", getEmail(scimUser), scimUser.getGivenName(),
							scimUser.getFamilyName());
				}
			}
		}
		catch (ScimResourceNotFoundException e) {
			// ignore
		}
		if (!lookup) {
			throw new ScimResourceNotFoundException("No user with id=" + userId);
		}
		List<ScimUser> users = dao.retrieveUsers("username eq '" + userId + "'");
		if (users.isEmpty()) {
			throw new ScimResourceNotFoundException("No user with username=" + userId);
		}
		if (users.size() != 1) {
			throw new ScimResourceConstraintFailedException("No unique user with username=" + userId);
		}
		ScimUser scimUser = users.get(0);
		return new UaaUser(scimUser.getUserName(), "N/A", getEmail(scimUser), scimUser.getGivenName(),
				scimUser.getFamilyName());
	}

	private String getEmail(ScimUser scimUser) {
		List<Email> emails = scimUser.getEmails();
		if (emails.isEmpty()) {
			return scimUser.getUserName().contains("@") ? scimUser.getUserName() : null;
		}
		for (Email email : emails) {
			if (email.isPrimary()) {
				return email.getValue();
			}
		}
		return scimUser.getEmails().get(0).getValue();
	}

	@ExceptionHandler
	public View handleException(ScimResourceNotFoundException e, Principal principal) {
		publish(new NoUserPasswordFailureEvent(e.getMessage(), principal));
		// There's no point throwing BadCredentialsException here because it is caught and
		// logged (then ignored) by the caller.
		return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(
				new BadCredentialsException("Invalid password change request"), false), HttpStatus.UNAUTHORIZED),
				messageConverters);
	}

	@ExceptionHandler
	public View handleException(ScimException e) {
		// No need to log the underlying exception (it will be logged by the caller)
		return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(
				new BadCredentialsException("Invalid password change request"), false), e.getStatus()),
				messageConverters);
	}

	private void checkPasswordChangeIsAllowed(String userId, String oldPassword) {
		if (securityContextAccessor.isClient()) {
			// Trusted client (not acting on behalf of user)
			return;
		}

		// Call is by or on behalf of end user
		String currentUser = securityContextAccessor.getUserId();

		if (securityContextAccessor.isAdmin()) {

			// even an admin needs to provide the old value to change his password
			if (userId.equals(currentUser) && !StringUtils.hasText(oldPassword)) {
				throw new InvalidPasswordException("Previous password is required even for admin");
			}

		}
		else {

			if (!userId.equals(currentUser)) {
				logger.warn("User with id " + currentUser + " attempting to change password for user " + userId);
				// TODO: This should be audited when we have non-authentication events in the log
				throw new InvalidPasswordException("Not permitted to change another user's password");
			}

			// User is changing their own password, old password is required
			if (!StringUtils.hasText(oldPassword)) {
				throw new InvalidPasswordException("Previous password is required");
			}

		}

	}
}
