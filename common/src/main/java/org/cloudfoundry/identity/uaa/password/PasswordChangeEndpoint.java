package org.cloudfoundry.identity.uaa.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.SimpleMessage;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.concurrent.atomic.AtomicInteger;

@Controller
@ManagedResource
public class PasswordChangeEndpoint {

	private final Log logger = LogFactory.getLog(getClass());

	private AtomicInteger scimPasswordChanges = new AtomicInteger();

	private ScimUserProvisioning dao;

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

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
		if (!dao.changePassword(userId, change.getOldPassword(), change.getPassword())) {
			throw new InvalidPasswordException("Password not changed for user: " + userId);
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
				throw new InvalidPasswordException("Previous password is required even for admin");
			}

		}
		else {

			if (!userId.equals(currentUser)) {
				logger.warn("User with id " + currentUser + " attempting to change password for user " + userId);
				// TODO: This should be audited when we have non-authentication events in the log
				throw new InvalidPasswordException("Bad request. Not permitted to change another user's password");
			}

			// User is changing their own password, old password is required
			if (!StringUtils.hasText(oldPassword)) {
				throw new InvalidPasswordException("Previous password is required");
			}

		}

	}
}
