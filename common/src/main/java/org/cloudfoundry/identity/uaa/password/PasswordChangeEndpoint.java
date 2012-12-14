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
package org.cloudfoundry.identity.uaa.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.message.SimpleMessage;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

@Controller
public class PasswordChangeEndpoint {

	private final Log logger = LogFactory.getLog(getClass());

	private ScimUserProvisioning dao;

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
			new HttpMessageConverter<?>[0]);
	
	public void setScimUserProvisioning(ScimUserProvisioning provisioning) {
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

	void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	@RequestMapping(value = "/Users/{userId}/password", method = RequestMethod.PUT)
	@ResponseBody
	public SimpleMessage changePassword(@PathVariable String userId, @RequestBody PasswordChangeRequest change) {
		checkPasswordChangeIsAllowed(userId, change.getOldPassword());
		if (!dao.changePassword(userId, change.getOldPassword(), change.getPassword())) {
			throw new InvalidPasswordException("Password not changed for user: " + userId);
		}
		return new SimpleMessage("ok", "password updated");
	}

	@ExceptionHandler
	public View handleException(ScimResourceNotFoundException e) {
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
