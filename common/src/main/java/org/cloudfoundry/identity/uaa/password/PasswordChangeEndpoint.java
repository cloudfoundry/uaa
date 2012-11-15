package org.cloudfoundry.identity.uaa.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.rest.SimpleMessage;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@Controller
@ManagedResource
public class PasswordChangeEndpoint {

	private final Log logger = LogFactory.getLog(getClass());

	private AtomicInteger scimPasswordChanges = new AtomicInteger();

	private ScimUserProvisioning dao;

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
																												   new HttpMessageConverter<?>[0]);

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
		this.statuses = statuses;
	}

	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	public PasswordChangeEndpoint(ScimUserProvisioning provisioning) {
		this.dao = provisioning;
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Password Change Count (Since Startup)")
	public int getUserPasswordChanges() {
		return scimPasswordChanges.get();
	}

	@RequestMapping(value = "/Users/{userId}/password", method = RequestMethod.PUT)
	@ResponseBody
	public SimpleMessage changePassword(@PathVariable String userId, @RequestBody PasswordChangeRequest change) {
		checkPasswordChangeIsAllowed(userId, change.getOldPassword());
		try {
			dao.changePassword(userId, change.getOldPassword(), change.getPassword());
		} catch (OptimisticLockingFailureException ex) {
			logger.error("error updating password", ex);
			throw new ScimResourceConflictException(ex.getMessage());
		} catch (ScimResourceNotFoundException ex) {
			logger.error("Attempt to change password for a non-existent user", ex);
			throw new BadCredentialsException("Invalid credentials");
		}
		scimPasswordChanges.incrementAndGet();
		return new SimpleMessage("ok", "password updated");
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
				throw new BadCredentialsException("Previous password is required even for admin");
			}

		}
		else {

			if (!userId.equals(currentUser)) {
				logger.warn("User with id " + currentUser + " attempting to change password for user " + userId);
				// TODO: This should be audited when we have non-authentication events in the log
				throw new BadCredentialsException("Bad request. Not permitted to change another user's password");
			}

			// User is changing their own password, old password is required
			if (!StringUtils.hasText(oldPassword)) {
				throw new BadCredentialsException("Previous password is required");
			}

		}

	}

	@ExceptionHandler
	public View handleException(Exception t, HttpServletRequest request) throws ScimException {
		ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
		if (t instanceof ScimException) {
			e = (ScimException) t;
		} else {
			Class<?> clazz = t.getClass();
			for (Class<?> key : statuses.keySet()) {
				if (key.isAssignableFrom(clazz)) {
					e = new ScimException(t.getMessage(), t, statuses.get(key));
					break;
				}
			}
		}

		// User can supply trace=true or just trace (unspecified) to get stack traces
		boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
		return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, trace),
																					  e.getStatus()), messageConverters);
	}
}
