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

package org.cloudfoundry.identity.uaa.scim;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.View;

/**
 * @author Dave Syer
 * 
 */
@Controller
public class GroupsUsersEndpoints implements InitializingBean {

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	private ScimUserEndpoints scimUserEndpoints;

	private Set<Pattern> patterns = new HashSet<Pattern>();

	{
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) eq (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) co (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) sw (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) gt (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) ge (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) lt (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("(.*?)([a-z0-9]*) le (.*?)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
		patterns.add(Pattern.compile("pr (.*?)([a-z0-9]*)([\\s]*.*)", Pattern.CASE_INSENSITIVE));
	}

	void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	/**
	 * @param scimUserEndpoints the scimUserEndpoints to set
	 */
	public void setScimUserEndpoints(ScimUserEndpoints scimUserEndpoints) {
		this.scimUserEndpoints = scimUserEndpoints;
	}

	@RequestMapping(value = "/Groups/{group}/Users", method = RequestMethod.GET)
	@ResponseBody
	public SearchResults<Map<String, Object>> findUsers(@PathVariable String group,
			@RequestParam(required = false, defaultValue = "") String filter,
			@RequestParam(required = false, defaultValue = "ascending") String sortOrder,
			@RequestParam(required = false, defaultValue = "1") int startIndex,
			@RequestParam(required = false, defaultValue = "100") int count) {
		checkFilter(filter);
		checkGroup(group);
		String appended = filter.trim();
		appended = (appended.length() > 0 ? "(" : "") + appended + (appended.length() > 0 ? ") and " : "")
				+ "groups.display co '" + group + "'";
		return scimUserEndpoints.findUsers("id,userName", appended, "userName", sortOrder, startIndex, count);
	}

	@ExceptionHandler
	public View handleException(Exception t, HttpServletRequest request) throws ScimException {
		return scimUserEndpoints.handleException(t, request);
	}

	private void checkFilter(String filter) {
		String lowerCase = filter.toLowerCase();
		if (lowerCase.contains("groups.")) {
			throw new ScimException(
					"Invalid filter expression: [" + filter + "] (no group filters allowed on /Groups)",
					HttpStatus.BAD_REQUEST);
		}
		for (Pattern pattern : patterns) {
			Matcher matcher = pattern.matcher(lowerCase);
			if (matcher.matches()) {
				String field = matcher.group(2);
				if (!"username".equals(field) && !"id".equals(field)) {
					throw new ScimException("Invalid filter expression: [" + filter + "] (no " + field
							+ " filters allowed on /Groups)", HttpStatus.BAD_REQUEST);
				}
			}
		}
	}

	private void checkGroup(String group) {
		if (securityContextAccessor.isClient() || securityContextAccessor.isAdmin()) {
			return;
		}
		Collection<? extends GrantedAuthority> authorities = securityContextAccessor.getAuthorities();
		Set<String> values = AuthorityUtils.authorityListToSet(authorities);
		if (!values.contains(group)) {
			throw new ScimException("Current user is not in requested group: " + group, HttpStatus.FORBIDDEN);
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(scimUserEndpoints, "ScimUserEndpoints must be set");
	}
}
