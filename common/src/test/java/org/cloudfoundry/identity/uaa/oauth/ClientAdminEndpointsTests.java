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

package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

/**
 * @author Dave Syer
 * 
 */
public class ClientAdminEndpointsTests {

	private ClientAdminEndpoints endpoints = new ClientAdminEndpoints();

	private BaseClientDetails details = new BaseClientDetails();

	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

	private ClientRegistrationService clientRegistrationService = Mockito.mock(ClientRegistrationService.class);
	
	@Rule
	public ExpectedException expected = ExpectedException.none();

	@Before
	public void setUp() {
		endpoints.setClientDetailsService(clientDetailsService);
		endpoints.setClientRegistrationService(clientRegistrationService);
		details.setClientId("foo");
		details.setClientSecret("secret");
		details.setAuthorizedGrantTypes(Arrays.asList("password"));
	}

	@Test
	public void testCreateClientDetails() throws Exception {
		ResponseEntity<Void> result = endpoints.createClientDetails(details);
		assertEquals(HttpStatus.CREATED, result.getStatusCode());
		Mockito.verify(clientRegistrationService).addClientDetails(details);
	}

	@Test
	public void testUpdateClientDetails() throws Exception {
		endpoints.createClientDetails(details);
		details.setScope(Arrays.asList("read"));
		ResponseEntity<Void> result = endpoints.updateClientDetails(details, "foo");
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
		Mockito.verify(clientRegistrationService).updateClientDetails(details);
	}

	@Test
	public void testChangeSecret() throws Exception {

		when(clientDetailsService.loadClientByClientId(details.getClientId())).thenReturn(details);		

		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getClientId()).thenReturn(details.getClientId());
		when(sca.isClient()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);

		SecretChangeRequest change = new SecretChangeRequest();
		change.setOldSecret(details.getClientSecret());
		change.setSecret("newpassword");
		endpoints.changeSecret(details.getClientId(), change);
		BaseClientDetails updated = new BaseClientDetails(details);
		updated.setClientSecret(change.getSecret());
		Mockito.verify(clientRegistrationService).updateClientDetails(updated );

	}

	@Test
	public void testChangeSecretDeniedForUser() throws Exception {

		when(clientDetailsService.loadClientByClientId(details.getClientId())).thenReturn(details);		

		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getClientId()).thenReturn(details.getClientId());
		when(sca.isClient()).thenReturn(false);
		endpoints.setSecurityContextAccessor(sca);

		SecretChangeRequest change = new SecretChangeRequest();
		change.setOldSecret(details.getClientSecret());
		change.setSecret("newpassword");
		expected.expect(IllegalStateException.class);
		expected.expectMessage("Only a client");
		endpoints.changeSecret(details.getClientId(), change);

	}

	@Test
	public void testChangeSecretDeniedForNonAdmin() throws Exception {

		when(clientDetailsService.loadClientByClientId(details.getClientId())).thenReturn(details);		

		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getClientId()).thenReturn("bar");
		when(sca.isClient()).thenReturn(true);
		when(sca.isAdmin()).thenReturn(false);
		endpoints.setSecurityContextAccessor(sca);

		SecretChangeRequest change = new SecretChangeRequest();
		change.setSecret("newpassword");
		expected.expect(IllegalStateException.class);
		expected.expectMessage("Not permitted to change");
		endpoints.changeSecret(details.getClientId(), change);

	}

	@Test
	public void testChangeSecretDeniedWhenOldSecretNotProvided() throws Exception {

		when(clientDetailsService.loadClientByClientId(details.getClientId())).thenReturn(details);		

		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getClientId()).thenReturn(details.getClientId());
		when(sca.isClient()).thenReturn(true);
		when(sca.isAdmin()).thenReturn(false);
		endpoints.setSecurityContextAccessor(sca);

		SecretChangeRequest change = new SecretChangeRequest();
		change.setSecret("newpassword");
		expected.expect(IllegalStateException.class);
		expected.expectMessage("Previous secret is required");
		endpoints.changeSecret(details.getClientId(), change);

	}

	@Test
	public void testChangeSecretDeniedWhenOldSecretNotProvidedEvenFormAdmin() throws Exception {

		when(clientDetailsService.loadClientByClientId(details.getClientId())).thenReturn(details);		

		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getClientId()).thenReturn(details.getClientId());
		when(sca.isClient()).thenReturn(true);
		when(sca.isAdmin()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);

		SecretChangeRequest change = new SecretChangeRequest();
		change.setSecret("newpassword");
		expected.expect(IllegalStateException.class);
		expected.expectMessage("Previous secret is required");
		endpoints.changeSecret(details.getClientId(), change);

	}

	@Test
	public void testChangeSecretByAdmin() throws Exception {

		when(clientDetailsService.loadClientByClientId(details.getClientId())).thenReturn(details);		

		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getClientId()).thenReturn("admin");
		when(sca.isClient()).thenReturn(true);
		when(sca.isAdmin()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);

		SecretChangeRequest change = new SecretChangeRequest();
		change.setOldSecret(details.getClientSecret());
		change.setSecret("newpassword");
		endpoints.changeSecret(details.getClientId(), change);
		BaseClientDetails updated = new BaseClientDetails(details);
		updated.setClientSecret(change.getSecret());
		Mockito.verify(clientRegistrationService).updateClientDetails(updated );

	}

	@Test
	public void testRemoveClientDetails() throws Exception {
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(details);
		endpoints.createClientDetails(details);
		ResponseEntity<Void> result = endpoints.removeClientDetails("foo");
		assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
		Mockito.verify(clientRegistrationService).removeClientDetails(details);
	}

	@Test
	public void testHandleNoSuchClient() throws Exception {
		ResponseEntity<Void> result = endpoints.handleNoSuchClient(new NoSuchClientException("No such client: foo"));
		assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
	}

	@Test
	public void testHandleClientAlreadyExists() throws Exception {
		ResponseEntity<Void> result = endpoints.handleClientAlreadyExists(new ClientAlreadyExistsException("No such client: foo"));
		assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
	}

}
