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
package org.cloudfoundry.identity.uaa.scim;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

/**
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
@Controller
public class ScimUserEndpoints implements InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());

	private ScimUserProvisioning dao;

	private Collection<String> schemas = Arrays.asList(ScimUser.SCHEMAS);

	private static final Random passwordGenerator = new SecureRandom();

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
			new HttpMessageConverter<?>[0]);

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	/**
	 * Set the message body converters to use.
	 * <p>
	 * These converters are used to convert from and to HTTP requests and responses.
	 */
	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	/**
	 * Map from exception type to Http status.
	 *
	 * @param statuses the statuses to set
	 */
	public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
		this.statuses = statuses;
	}

	private static String generatePassword() {
		byte[] bytes = new byte[16];
		passwordGenerator.nextBytes(bytes);
		return new String(Hex.encode(bytes));
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.GET)
	@ResponseBody
	public ScimUser getUser(@PathVariable String userId) {
		return dao.retrieveUser(userId);
	}

	@RequestMapping(value = "/User", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.CREATED)
	@ResponseBody
	public ScimUser createUser(@RequestBody ScimUser user) {
		return dao.createUser(user, generatePassword());
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.PUT)
	@ResponseBody
	public ScimUser updateUser(@RequestBody ScimUser user, @PathVariable String userId,
			@RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag) {
		if (etag.equals("NaN")) {
			throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
		}
		int version = getVersion(userId, etag);
		user.setVersion(version);
		return dao.updateUser(userId, user);
	}

	@RequestMapping(value = "/User/{userId}/password", method = RequestMethod.PUT)
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void changePassword(@PathVariable String userId, @RequestBody PasswordChangeRequest change) {
		checkPasswordChangeIsAllowed(userId, change.getOldPassword());

		if (!dao.changePassword(userId, change.getOldPassword(), change.getPassword())) {
			throw new ScimException("Password not changed for user: " + userId, HttpStatus.BAD_REQUEST);
		}
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
				throw new ScimException("Previous password is required even for admin", HttpStatus.BAD_REQUEST);
			}

		} else {

			if (!userId.equals(currentUser)) {
				logger.warn("User with id " + currentUser + " attempting to change password for user " + userId);
				// TODO: This should be audited when we have non-authentication events in the log
				throw new ScimException("Bad request. Not permitted to change another user's password", HttpStatus.BAD_REQUEST);
			}			

			// User is changing their own password, old password is required
			if (!StringUtils.hasText(oldPassword)) {
				throw new ScimException("Previous password is required", HttpStatus.BAD_REQUEST);
			}

		}


	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.DELETE)
	@ResponseBody
	public ScimUser deleteUser(@PathVariable String userId,
			@RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag) {
		if (etag.equals("NaN")) {
			throw new ScimException("Missing If-Match for DELETE", HttpStatus.BAD_REQUEST);
		}
		int version = getVersion(userId, etag);
		return dao.removeUser(userId, version);
	}

	private int getVersion(String userId, String etag) {
		String value = etag.trim();
		if (value.equals("*")) {
			return dao.retrieveUser(userId).getVersion();
		}
		while (value.startsWith("\"")) {
			value = value.substring(1);
		}
		while (value.endsWith("\"")) {
			value = value.substring(0, value.length() - 1);
		}
		try {
			return Integer.valueOf(value);
		}
		catch (NumberFormatException e) {
			throw new ScimException("Invalid version match header (should be a version number): " + etag,
					HttpStatus.BAD_REQUEST);
		}
	}

	@RequestMapping(value = "/Users", method = RequestMethod.GET)
	@ResponseBody
	public SearchResults<Map<String, Object>> findUsers(
			@RequestParam(required = false, defaultValue = "id") String attributesCommaSeparated,
			@RequestParam(required = false, defaultValue = "id pr") String filter,
			@RequestParam(required = false, defaultValue = "1") int startIndex,
			@RequestParam(required = false, defaultValue = "100") int count) {

		Collection<ScimUser> input = dao.retrieveUsers(filter);
		String[] attributes = attributesCommaSeparated.split(",");
		Map<String, Expression> expressions = new LinkedHashMap<String, Expression>();

		for (String attribute : attributes) {

			String spel = attribute.replaceAll("emails\\.(.*)", "emails.![$1]");
			logger.debug("Registering SpEL for attribute: " + spel);

			Expression expression;
			try {
				expression = new SpelExpressionParser().parseExpression(spel);
			}
			catch (SpelParseException e) {
				throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
			}

			expressions.put(attribute, expression);

		}

		Collection<Map<String, Object>> users = new ArrayList<Map<String, Object>>();
		StandardEvaluationContext context = new StandardEvaluationContext();
		for (ScimUser user : input) {
			Map<String, Object> map = new LinkedHashMap<String, Object>();
			for (String attribute : expressions.keySet()) {
				map.put(attribute, expressions.get(attribute).getValue(context, user));
			}
			users.add(map);
		}

		return new SearchResults<Map<String, Object>>(schemas, users, 1, users.size(), users.size());

	}

	@ExceptionHandler
	public View handleException(Exception t) throws ScimException {
		ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
		if (t instanceof ScimException) {
			e = (ScimException) t;
		}
		else {
			Class<?> clazz = t.getClass();
			for (Class<?> key : statuses.keySet()) {
				if (key.isAssignableFrom(clazz)) {
					e = new ScimException(t.getMessage(), t, statuses.get(key));
					break;
				}
			}
		}
		return new ConvertingExceptionView(new ResponseEntity<Exception>(e, e.getStatus()),  messageConverters);
	}

	public void setScimUserProvisioning(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "Dao must be set");
	}
}
