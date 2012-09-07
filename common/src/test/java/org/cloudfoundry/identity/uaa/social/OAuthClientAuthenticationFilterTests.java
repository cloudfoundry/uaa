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

package org.cloudfoundry.identity.uaa.social;

import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Assume;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl;
import org.springframework.security.oauth.consumer.BaseProtectedResourceDetails;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.OAuthSecurityContextHolder;
import org.springframework.security.oauth.consumer.OAuthSecurityContextImpl;
import org.springframework.security.oauth.consumer.client.OAuthRestTemplate;

/**
 * @author Dave Syer
 * 
 */
public class OAuthClientAuthenticationFilterTests {

	private SocialClientAuthenticationFilter filter = new SocialClientAuthenticationFilter("/login");

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private BaseProtectedResourceDetails resource = new BaseProtectedResourceDetails();

	private void setUpContext(String tokenName, String secretName, String keyName, String sharedName) {
		resource.setId("foo");
		String consumerKey = System.getProperty(keyName);
		Assume.assumeNotNull(consumerKey);
		String sharedSecret = System.getProperty(sharedName);
		Assume.assumeNotNull(sharedSecret);
		String accessToken = System.getProperty(tokenName);
		Assume.assumeNotNull(accessToken);
		String secret = System.getProperty(secretName);
		Assume.assumeNotNull(accessToken);
		OAuthSecurityContextImpl context = new OAuthSecurityContextImpl();
		OAuthConsumerToken token = new OAuthConsumerToken();
		resource.setConsumerKey(consumerKey);
		resource.setSharedSecret(new SharedConsumerSecretImpl(sharedSecret));
		token.setValue(accessToken);
		token.setSecret(secret);
		context.setAccessTokens(Collections.singletonMap("foo", token));
		OAuthSecurityContextHolder.setContext(context);
	}

	@Test
	public void testFacebookAuthentication() throws Exception {
		OAuthRestTemplate restTemplate = new OAuthRestTemplate(resource);
		setUpContext("twitter.token", "twitter.secret", "twitter.key", "twitter.shared");
		filter.setRestTemplate(restTemplate);
		filter.setUserInfoUrl("https://api.twitter.com/1/account/verify_credentials.json");
		filter.afterPropertiesSet();
		Authentication authentication = filter.attemptAuthentication(request, response);
		System.err.println(authentication.getDetails());
		assertTrue(authentication.isAuthenticated());
	}

	@Test
	public void testLinkedInAuthentication() throws Exception {
		OAuthRestTemplate restTemplate = new OAuthRestTemplate(resource);
		setUpContext("linked.token", "linked.secret", "linked.key", "linked.shared");
		filter.setRestTemplate(restTemplate);
		filter.setUserInfoUrl("http://api.linkedin.com/v1/people/~:(id,first-name,last-name,formatted-name,api-standard-profile-request,public-profile-url)?format=json");
		filter.afterPropertiesSet();
		Authentication authentication = filter.attemptAuthentication(request, response);
		System.err.println(authentication.getDetails());
		assertTrue(authentication.isAuthenticated());
	}

}
