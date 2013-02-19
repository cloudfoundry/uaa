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

package org.cloudfoundry.identity.uaa.scim.remote;

import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.remote.RemoteScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mockito;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;

import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * @author Dave Syer
 * 
 */
public class RemoteScimUserProvisioningTests {

	private RemoteScimUserProvisioning service = new RemoteScimUserProvisioning();

	private RestOperations restTemplate = Mockito.mock(RestOperations.class);

	private ScimUser user;

	@Before
	public void start() {
		service.setRestTemplate(restTemplate);
		service.setBaseUrl("http://base");
		user = new ScimUser("1234", "foo", "Foo", "Bar");
		user.addEmail("foo@bar.com");
	}

	@After
	public void stop() {
	}

	@Test
	public void testRetrieveUser() {
		service.retrieve("1234");
		Mockito.verify(restTemplate).getForObject("http://base/User/{id}", ScimUser.class, "1234");
	}

	@Test
	public void testRetrieveUsers() {
		service.retrieveAll();
		Mockito.verify(restTemplate).getForObject("http://base/Users", List.class);
	}

	@Test
	public void testFilterUsers() {
		service.query("name eq 'foo'");
		Mockito.verify(restTemplate).getForObject("http://base/Users?filter={filter}", List.class, "name eq 'foo'");
	}

	@Test
	public void testCreateUser() {
		service.createUser(user, "password");
		assertEquals("password", user.getPassword());
		Mockito.verify(restTemplate).postForObject("http://base/User", user, ScimUser.class);
	}

	@Test
	public void testChangePassword() {
		service.changePassword("1234", "oldPassword", "newPassword");
		Mockito.verify(restTemplate).put(Mockito.eq("http://base/User/{id}/password"),
				Mockito.any(PasswordChangeRequest.class), Mockito.eq("1234"));
	}

	@Test
	public void testUpdateUser() {
		service.update("1234", user);
		Mockito.verify(restTemplate).put("http://base/User/{id}", user, "1234");
	}

	@Test
	public void testRemoveUser() {
		HttpHeaders headers = new HttpHeaders();
		headers.set("If-Match", "123456789");
		Mockito.when(
				restTemplate.exchange(Mockito.eq("http://base/User/{id}"), Mockito.eq(HttpMethod.DELETE),
						Mockito.argThat(new HttpHeadersMatcher()), Mockito.eq(ScimUser.class), Mockito.eq("1234")))
				.thenReturn(new ResponseEntity<ScimUser>(user, HttpStatus.OK));
		service.delete("1234", 123456789);
	}

	private static class HttpHeadersMatcher extends ArgumentMatcher<HttpEntity<Void>> {

		private String key = "If-Match";

		private String value = "123456789";

		@Override
		public boolean matches(Object argument) {
			@SuppressWarnings("unchecked")
			String actual = ((HttpEntity<Void>) argument).getHeaders().getFirst(key);
			return actual.equals(value);
		}

	}

}
