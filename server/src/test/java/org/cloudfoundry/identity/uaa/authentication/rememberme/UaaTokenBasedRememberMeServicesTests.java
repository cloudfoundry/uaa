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

import java.util.Date;

import javax.servlet.http.Cookie;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * 
 * @author Stephane CIZERON
 *
 */
public class UaaTokenBasedRememberMeServicesTests {

	private UaaTokenBasedRememberMeServices rememberMeServices;
	
	private UaaUserDatabase uaaUserDatabase;
	
	@org.junit.Before
	public void newContext() {
		this.uaaUserDatabase = Mockito.mock(UaaUserDatabase.class);
		this.rememberMeServices = new UaaTokenBasedRememberMeServices("123", "79491918F8C3EAA525424C296D90B3C8", "C75984A550C4CD81ACD44AF92BB91CAB", this.uaaUserDatabase);
		this.rememberMeServices.setTokenValiditySeconds(50*365*24*60*60); // it will expire in 50 years, so we have time ...

	}
	
	/**
	 * we assert that the remember me is part of the response
	 */
	@Test 
	public void onLoginSuccess() {
		// given
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setParameter("remember-me", "true");
		request.setParameter("User-Agent","my-user-agent");
		
		Authentication successfulAuthentication = Mockito.mock(Authentication.class);
		UaaPrincipal uaaPrincipal = Mockito.mock(UaaPrincipal.class);
		UaaUser uaaUser = Mockito.mock(UaaUser.class);
		Mockito.when(uaaUser.getModified()).thenReturn(new Date(1322018752992l));
		Mockito.when(successfulAuthentication.getPrincipal()).thenReturn(uaaPrincipal);
		Mockito.when(uaaPrincipal.getId()).thenReturn("d0f52125-1c30-42c4-93d4-5ab6cff9be68");
		Mockito.when(this.uaaUserDatabase.retrieveUserById(Mockito.eq("d0f52125-1c30-42c4-93d4-5ab6cff9be68"))).thenReturn(uaaUser);
		
		// when
		this.rememberMeServices.loginSuccess(request, response, successfulAuthentication);
		
		// then
		Assert.assertThat(response.getCookie("remember-me"), CoreMatchers.notNullValue());
		Assert.assertThat(response.getCookie("remember-me").getValue(), CoreMatchers.notNullValue());
	}
	
	@Test
	public void autoLogin() {
		// given
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		Cookie cookie = new Cookie("remember-me", "T1pkNzJscnU3ZytzQno0LzVqTkFXcTEvTVhSbERGMDRSdWxKU3JMQ1N2TkJVUVE1WDEzem5QL3g5YVdEZExLVjozMDU2ODcyNDQ0MDA2OmVjOTI5MTUwMzRlMzEwOTI0NGVjNjZkYWQ2OGE2ZDhmZTM5ZjFmNWM1MmU1YzYxZDU4MzRiNzNjMjBlMjAzYjg");
		request.setCookies(cookie);
		
		UaaUser uaaUser = Mockito.mock(UaaUser.class);
		Mockito.when(uaaUser.getId()).thenReturn("d0f52125-1c30-42c4-93d4-5ab6cff9be68");
		Mockito.when(uaaUser.getModified()).thenReturn(new Date(1322018752992l));
		Mockito.when(uaaUser.getUsername()).thenReturn("marissa");
		Mockito.when(uaaUser.getPassword()).thenReturn("koala");
		Mockito.when(this.uaaUserDatabase.retrieveUserById(Mockito.eq("d0f52125-1c30-42c4-93d4-5ab6cff9be68"))).thenReturn(uaaUser);
	
		// when		
		Authentication authentication = this.rememberMeServices.autoLogin(request, response);
		
		// then 
		Assert.assertThat(authentication, CoreMatchers.notNullValue());
		Assert.assertThat(authentication instanceof RememberMeAuthenticationToken, CoreMatchers.is(true));
		Assert.assertThat(authentication.getPrincipal() instanceof UaaPrincipal, CoreMatchers.is(true));
		Assert.assertThat(((UaaPrincipal)authentication.getPrincipal()).getId(), CoreMatchers.is("d0f52125-1c30-42c4-93d4-5ab6cff9be68"));
	}

	@Test
	public void noRememberMeCookie()  {
		// given
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		// when		
		Authentication authentication = this.rememberMeServices.autoLogin(request, response);
		// then
		Assert.assertThat(authentication, CoreMatchers.nullValue());
	}

	
	@Test
	public void invalidCookie()  {
		// given
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();	
		Cookie cookie = new Cookie("remember-me", "invalid");
		request.setCookies(cookie);

		// when		
		Authentication authentication = this.rememberMeServices.autoLogin(request, response);

		// then
		Assert.assertThat(authentication, CoreMatchers.nullValue());
		Assert.assertThat(response.getCookie("remember-me"), CoreMatchers.notNullValue());
		Assert.assertThat(response.getCookie("remember-me").getMaxAge(), CoreMatchers.is(0));
	}
	
	@Test
	public void unknowUser()  {
		// given
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		Cookie cookie = new Cookie("remember-me", "T1pkNzJscnU3ZytzQno0LzVqTkFXcTEvTVhSbERGMDRSdWxKU3JMQ1N2TkJVUVE1WDEzem5QL3g5YVdEZExLVjozMDU2ODcyNDQ0MDA2OmVjOTI5MTUwMzRlMzEwOTI0NGVjNjZkYWQ2OGE2ZDhmZTM5ZjFmNWM1MmU1YzYxZDU4MzRiNzNjMjBlMjAzYjg");
		request.setCookies(cookie);

		// when		
		Authentication authentication = this.rememberMeServices.autoLogin(request, response);

		// then
		Assert.assertThat(authentication, CoreMatchers.nullValue());
		Assert.assertThat(response.getCookie("remember-me"), CoreMatchers.notNullValue());
		Assert.assertThat(response.getCookie("remember-me").getMaxAge(), CoreMatchers.is(0));
	}
}
