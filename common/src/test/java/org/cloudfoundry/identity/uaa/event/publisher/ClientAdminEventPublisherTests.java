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

package org.cloudfoundry.identity.uaa.event.publisher;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.event.PasswordFailureEvent;
import org.cloudfoundry.identity.uaa.event.SecretChangeEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class ClientAdminEventPublisherTests {

	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

	private ClientAdminEventPublisher subject = new ClientAdminEventPublisher(clientDetailsService);

	private ApplicationEventPublisher publisher = Mockito.mock(ApplicationEventPublisher.class);

	@Before
	public void init() {
		subject.setApplicationEventPublisher(publisher);
		Authentication authentication = new OAuth2Authentication(new DefaultAuthorizationRequest("client",
				Arrays.asList("read")), UaaAuthenticationTestFactory.getAuthentication("ID", "joe", "joe@test.org"));
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@After
	public void destroy() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testSecretChange() {
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(
				new BaseClientDetails("foo", null, null, "client_credentials", "none"));
		subject.secretChange("foo");
		Mockito.verify(publisher).publishEvent(Mockito.any(SecretChangeEvent.class));
	}

	@Test
	public void testSecretFailure() {
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(
				new BaseClientDetails("foo", null, null, "client_credentials", "none"));
		subject.secretFailure("foo", new RuntimeException("planned"));
		Mockito.verify(publisher).publishEvent(Mockito.any(PasswordFailureEvent.class));
	}

	@Test
	public void testSecretFailureMissingClient() {
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenThrow(new InvalidClientException("Not found"));
		subject.secretFailure("foo", new RuntimeException("planned"));
		Mockito.verify(publisher).publishEvent(Mockito.any(PasswordFailureEvent.class));
	}
}
