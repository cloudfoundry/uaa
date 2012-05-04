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

package org.cloudfoundry.identity.uaa.web;

import static org.junit.Assert.assertNotNull;

import java.util.Locale;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.View;

/**
 * @author Dave Syer
 * 
 */
public class ForwardAwareInternalResourceViewResolverTests {
	
	private ForwardAwareInternalResourceViewResolver resolver = new ForwardAwareInternalResourceViewResolver();

	private MockHttpServletRequest request = new MockHttpServletRequest();
	
	@Before
	public void start() {
		ServletRequestAttributes attributes = new ServletRequestAttributes(request );
		LocaleContextHolder.setLocale(request.getLocale());
		RequestContextHolder.setRequestAttributes(attributes);
	}

	@After
	public void clean() {
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void testResolveNonForward() throws Exception {
		resolver.setApplicationContext(new GenericApplicationContext());
		View view = resolver.resolveViewName("foo", Locale.US);
		assertNotNull(view);
	}

	@Test
	public void testResolveRedirect() throws Exception {
		resolver.setApplicationContext(new GenericApplicationContext());
		View view = resolver.resolveViewName("redirect:foo", Locale.US);
		assertNotNull(view);
	}

	@Test
	public void testResolveForwardWithAccept() throws Exception {
		request.addHeader("Accept", "application/json");
		resolver.setApplicationContext(new GenericApplicationContext());
		View view = resolver.resolveViewName("forward:foo", Locale.US);
		assertNotNull(view);
	}

	@Test
	public void testResolveForwardWithUnparseableAccept() throws Exception {
		request.addHeader("Accept", "bar");
		resolver.setApplicationContext(new GenericApplicationContext());
		View view = resolver.resolveViewName("forward:foo", Locale.US);
		assertNotNull(view);
	}

}
