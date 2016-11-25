/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication.rememberme;

import java.io.IOException;

import javax.servlet.ServletException;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * 
 * @author Stephane CIZERON
 *
 */
public class SamlLoginRememberMeAwareFilterTests {

	private SamlLoginRememberMeAwareFilter filter;

	@Test
	public void enabledFromConstructor() throws IOException, ServletException {
		this.filter = new SamlLoginRememberMeAwareFilter(Boolean.TRUE);
		MockFilterChain chain = doFilter();
		assertEnabled(chain);
	}

	@Test
	public void disabledFromConstructor() throws IOException, ServletException {
		this.filter = new SamlLoginRememberMeAwareFilter(Boolean.FALSE);
		MockFilterChain chain = doFilter();
		assertDisabled(chain);
	}
	
	@Test
	public void enabledFromFilterConfig() throws ServletException, IOException {
		this.filter = new SamlLoginRememberMeAwareFilter();
		MockFilterConfig filterConfig = new MockFilterConfig();
		filterConfig.addInitParameter("enabledForSaml", "true");
		this.filter.init(filterConfig);
		MockFilterChain chain = doFilter();
		assertEnabled(chain);
	}
	
	@Test
	public void disabledFromFilterConfig() throws ServletException, IOException {
		this.filter = new SamlLoginRememberMeAwareFilter();
		MockFilterConfig filterConfig = new MockFilterConfig();
		this.filter.init(filterConfig);
		MockFilterChain chain = doFilter();
		assertDisabled(chain);
	}
	
	/**
	 * 
	 * @param chain
	 */
	private void assertEnabled(MockFilterChain chain) {
		Assert.assertThat("the original request is wrapped",
				chain.getRequest() instanceof SamlLoginRememberMeAwareFilter.RememberMeRequestWrapper,
				CoreMatchers.is(true));
		Assert.assertThat("the original request is wrapped and returns \"true\" when getting \"remember-me\" parameter",
				chain.getRequest().getParameter("remember-me"), CoreMatchers.is("true"));
	}

	/**
	 * 
	 * @param chain
	 */
	private void assertDisabled(MockFilterChain chain) {
		Assert.assertThat("the original request is not wrapped",
				chain.getRequest() instanceof SamlLoginRememberMeAwareFilter.RememberMeRequestWrapper,
				CoreMatchers.is(false));
		Assert.assertThat("the original request has no \"remember-me\" parameter",
				chain.getRequest().getParameter("remember-me"), CoreMatchers.nullValue());
	}

	/**
	 * 
	 * @return
	 * @throws IOException
	 * @throws ServletException
	 */
	private MockFilterChain doFilter() throws IOException, ServletException {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		this.filter.doFilter(request, response, chain);
		return chain;
	}
}
