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
package org.cloudfoundry.identity.uaa;

import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class SecurityTests {

	private GenericXmlApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private AccessDecisionManager accessDecisionManager;

	private Authentication authentication;

	@After
	public void cleanup() throws Exception {
		if (context != null) {
			context.close();
		}
	}

	@Before
	public void start() {
		context = new GenericXmlApplicationContext("classpath:test-security.xml");
		accessDecisionManager = context.getBean("accessDecisionManager", AccessDecisionManager.class);
		authentication = new TestingAuthenticationToken("foo", "bar", AuthorityUtils.createAuthorityList("ROLE_USER",
				"ROLE_ADMIN"));
	}

	@Test
	public void testSimpleUser() throws Exception {
		accessDecisionManager.decide(authentication, null,
				Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_USER")));
	}

	@Test
	public void testAdminUser() throws Exception {
		accessDecisionManager.decide(authentication, null,
				Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_USER"), new SecurityConfig("ROLE_ADMIN")));
	}

	@Test
	public void testUserIsNotClient() throws Exception {
		expected.expect(AccessDeniedException.class);
		accessDecisionManager.decide(authentication, null,
				Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_CLIENT"), new SecurityConfig("ROLE_ADMIN")));
	}

	@Test
	public void testOAuthClient() throws Exception {
		authentication = new OAuth2Authentication(new AuthorizationRequest("foo",
				OAuth2Utils.parseParameterList("bar"), AuthorityUtils.createAuthorityList("ROLE_CLIENT", "ROLE_ADMIN"),
				null), null);
		accessDecisionManager.decide(authentication, null,
				Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_CLIENT"), new SecurityConfig("ROLE_ADMIN")));
	}

	@Test
	public void testOAuthUser() throws Exception {
		authentication = new OAuth2Authentication(new AuthorizationRequest("foo",
				OAuth2Utils.parseParameterList("bar"), AuthorityUtils.createAuthorityList("ROLE_CLIENT", "ROLE_ADMIN"),
				null), authentication);
		expected.expect(AccessDeniedException.class);
		accessDecisionManager.decide(authentication, null,
				Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_CLIENT"), new SecurityConfig("ROLE_ADMIN")));
	}
}