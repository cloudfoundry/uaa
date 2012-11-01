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
package org.cloudfoundry.identity.uaa.scim.users;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.scim.core.ScimException;
import org.cloudfoundry.identity.uaa.scim.core.ScimResourceConflictException;
import org.cloudfoundry.identity.uaa.scim.groups.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.query.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.scim.query.SearchResults;
import org.cloudfoundry.identity.uaa.scim.query.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.scim.query.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
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
 * User provisioning and query endpoints. Implements the core API from the Simple Cloud Identity Management (SCIM)
 * group. Exposes basic CRUD and query features for user accounts in a backend database.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 *
 * @see <a href="http://www.simplecloud.info">SCIM specs</a>
 */
@Controller
@ManagedResource
public class ScimUserEndpoints implements InitializingBean {

	private ScimUserProvisioning dao;

	private ScimGroupMembershipManager membershipManager;

	private static final Random passwordGenerator = new SecureRandom();

	private final Map<String, AtomicInteger> errorCounts = new ConcurrentHashMap<String, AtomicInteger>();

	private AtomicInteger scimUpdates = new AtomicInteger();

	private AtomicInteger scimDeletes = new AtomicInteger();

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
			new HttpMessageConverter<?>[0]);

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

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Total Users")
	public int getTotalUsers() {
		return dao.retrieveUsers().size();
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Account Update Count (Since Startup)")
	public int getUserUpdates() {
		return scimUpdates.get();
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Account Delete Count (Since Startup)")
	public int getUserDeletes() {
		return scimDeletes.get();
	}

	@ManagedMetric(displayName = "Error Counts")
	public Map<String, AtomicInteger> getErrorCounts() {
		return errorCounts;
	}

	@RequestMapping(value = "/Users/{userId}", method = RequestMethod.GET)
	@ResponseBody
	public ScimUser getUser(@PathVariable String userId) {
		return syncGroups(dao.retrieveUser(userId));
	}

	@RequestMapping(value = "/Users", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.CREATED)
	@ResponseBody
	public ScimUser createUser(@RequestBody ScimUser user) {
		return syncGroups(dao.createUser(user, user.getPassword() == null ? generatePassword() : user.getPassword()));
	}

	@RequestMapping(value = "/Users/{userId}", method = RequestMethod.PUT)
	@ResponseBody
	public ScimUser updateUser(@RequestBody ScimUser user, @PathVariable String userId,
			@RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag) {
		if (etag.equals("NaN")) {
			throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
		}
		int version = getVersion(userId, etag);
		user.setVersion(version);
		try {
			ScimUser updated = dao.updateUser(userId, user);
			scimUpdates.incrementAndGet();
			return syncGroups(updated);
		}
		catch (OptimisticLockingFailureException e) {
			throw new ScimResourceConflictException(e.getMessage());
		}
	}

	@RequestMapping(value = "/Users/{userId}", method = RequestMethod.DELETE)
	@ResponseBody
	public ScimUser deleteUser(@PathVariable String userId,
			@RequestHeader(value = "If-Match", required = false) String etag) {
		int version = etag == null ? -1 : getVersion(userId, etag);
		ScimUser user = getUser(userId);
		dao.removeUser(userId, version);
		membershipManager.removeMembersByMemberId(userId);
		scimDeletes.incrementAndGet();
		return user;
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
	public SearchResults<?> findUsers(
			@RequestParam(value = "attributes", required = false) String attributesCommaSeparated,
			@RequestParam(required = false, defaultValue = "id pr") String filter,
			@RequestParam(required = false) String sortBy,
			@RequestParam(required = false, defaultValue = "ascending") String sortOrder,
			@RequestParam(required = false, defaultValue = "1") int startIndex,
			@RequestParam(required = false, defaultValue = "100") int count) {

		if (startIndex<1) {
			startIndex = 1;
		}

		List<ScimUser> input;
		try {
			input = dao.retrieveUsers(filter, sortBy, sortOrder.equals("ascending"));
			for (ScimUser user : input.subList(startIndex - 1, startIndex + count - 1)) {
				syncGroups(user);
			}
		}
		catch (IllegalArgumentException e) {
			throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
		}

		if (!StringUtils.hasLength(attributesCommaSeparated)) {
			// Return all user data
			return new SearchResults<ScimUser>(Arrays.asList(ScimUser.SCHEMAS), input, startIndex, count, input.size());
		}

		AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.<String, String> singletonMap("emails\\.(.*)", "emails.![$1]"));
		String[] attributes = attributesCommaSeparated.split(",");
		try {
			return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, attributes, mapper, Arrays.asList(ScimUser.SCHEMAS));
		} catch (SpelParseException e) {
			throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
		} catch (SpelEvaluationException e) {
			throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
		}
	}

	private ScimUser syncGroups(ScimUser user) {
		if (user == null) {
			return user;
		}

		Set<ScimGroup> directGroups = membershipManager.getGroupsWithMember(user.getId(), false);
		Set<ScimGroup> indirectGroups = membershipManager.getGroupsWithMember(user.getId(), true);
		indirectGroups.removeAll(directGroups);
		Set<ScimUser.Group> groups = new HashSet<ScimUser.Group>();
		for (ScimGroup group : directGroups) {
			groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.MembershipType.DIRECT));
		}
		for (ScimGroup group : indirectGroups) {
			groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.MembershipType.INDIRECT));
		}

		user.setGroups(groups);
		return user;
	}

	@ExceptionHandler
	public View handleException(Exception t, HttpServletRequest request) throws ScimException {
		ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
		if (t instanceof ScimException) {
			e = (ScimException) t;
		}
		else if (t instanceof DataIntegrityViolationException) {
			e = new ScimException(t.getMessage(), t, HttpStatus.BAD_REQUEST);
		}
		else if (t instanceof HttpMessageConversionException) {
			e = new ScimException(t.getMessage(), t, HttpStatus.BAD_REQUEST);
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
		incrementErrorCounts(e);
		// User can supply trace=true or just trace (unspecified) to get stack traces
		boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
		return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, trace),
				e.getStatus()), messageConverters);
	}

	private void incrementErrorCounts(ScimException e) {
		String series = UaaStringUtils.getErrorName(e);
		AtomicInteger value = errorCounts.get(series);
		if (value==null) {
			synchronized (errorCounts) {
				value = errorCounts.get(series);
				if (value==null) {
					value = new AtomicInteger();
					errorCounts.put(series, value);
				}
			}
		}
		value.incrementAndGet();
	}

	public void setScimUserProvisioning(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	public void setScimGroupMembershipManager(ScimGroupMembershipManager membershipManager) {
		this.membershipManager = membershipManager;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "ScimUserProvisioning must be set");
		Assert.notNull(membershipManager, "ScimGroupMembershipManager must be set");
	}
}
