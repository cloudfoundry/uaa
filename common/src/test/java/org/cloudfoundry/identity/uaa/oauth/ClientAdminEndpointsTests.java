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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

/**
 * @author Dave Syer
 * 
 */
public class ClientAdminEndpointsTests {

	private ClientAdminEndpoints endpoints = new ClientAdminEndpoints();

	private BaseClientDetails input = new BaseClientDetails();

	private BaseClientDetails details = new BaseClientDetails();

	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

	private SecurityContextAccessor securityContextAccessor = Mockito.mock(SecurityContextAccessor.class);

	private ClientRegistrationService clientRegistrationService = Mockito.mock(ClientRegistrationService.class);

	@Rule
	public ExpectedException expected = ExpectedException.none();

	@Before
	public void setUp() throws Exception {
		endpoints.setClientDetailsService(clientDetailsService);
		endpoints.setClientRegistrationService(clientRegistrationService);
		endpoints.setSecurityContextAccessor(securityContextAccessor);
		input.setClientId("foo");
		input.setClientSecret("secret");
		input.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
		details = new BaseClientDetails(input);
		details.setResourceIds(Arrays.asList("none"));
		details.setScope(Arrays.asList("uaa.none"));
		details.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
		endpoints.afterPropertiesSet();
	}

	@Test
	public void testStatistics() throws Exception {
		assertEquals(0, endpoints.getClientDeletes());
		assertEquals(0, endpoints.getClientSecretChanges());
		assertEquals(0, endpoints.getClientUpdates());
		assertEquals(0, endpoints.getErrorCounts().size());
		assertEquals(0, endpoints.getTotalClients());
	}

	@Test
	public void testCreateClientDetails() throws Exception {
		ClientDetails result = endpoints.createClientDetails(input);
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).addClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void testCreateClientDetailsWithReservedId() throws Exception {
		input.setClientId("uaa");
		ClientDetails result = endpoints.createClientDetails(input);
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).addClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void testCreateClientDetailsWithNoGrantType() throws Exception {
		input.setAuthorizedGrantTypes(Collections.<String>emptySet());
		ClientDetails result = endpoints.createClientDetails(input);
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).addClientDetails(details);
	}

	@Test
	public void testCreateClientDetailsWithClientCredentials() throws Exception {
		input.setAuthorizedGrantTypes(Arrays.asList("client_credentials"));
		details.setAuthorizedGrantTypes(input.getAuthorizedGrantTypes());
		ClientDetails result = endpoints.createClientDetails(input);
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).addClientDetails(details);
	}

	@Test
	public void testResourceServerCreation() throws Exception {
		details.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.resource"));
		details.setScope(Arrays.asList(details.getClientId() + ".some"));
		details.setAuthorizedGrantTypes(Arrays.asList("client_credentials"));
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void testCreateClientDetailsWithPasswordGrant() throws Exception {
		input.setAuthorizedGrantTypes(Arrays.asList("password"));
		ClientDetails result = endpoints.createClientDetails(input);
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).addClientDetails(details);
	}

	@Test
	public void testFindClientDetails() throws Exception {
		Mockito.when(clientRegistrationService.listClientDetails()).thenReturn(Arrays.<ClientDetails> asList(details));
		Map<String, ClientDetails> result = endpoints.listClientDetails();
		assertEquals(1, result.size());
		Mockito.verify(clientRegistrationService).listClientDetails();
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void testUpdateClientDetailsWithNullCallerAndInvalidScope() throws Exception {
		endpoints.createClientDetails(input);
		input.setScope(Arrays.asList("read"));
		ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
		assertNull(result.getClientSecret());
		details.setScope(Arrays.asList("read"));
		Mockito.verify(clientRegistrationService).updateClientDetails(details);
	}

	@Test
	public void testUpdateClientDetails() throws Exception {
		endpoints.createClientDetails(input);
		input.setScope(Arrays.asList(input.getClientId() + ".read"));
		ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
		assertNull(result.getClientSecret());
		details.setScope(Arrays.asList(input.getClientId() + ".read"));
		Mockito.verify(clientRegistrationService).updateClientDetails(details);
	}

	@Test
	public void testPartialUpdateClientDetails() throws Exception {
		BaseClientDetails updated = new BaseClientDetails(details);
		input = new BaseClientDetails();
		input.setClientId("foo");
		Mockito.when(clientDetailsService.loadClientByClientId(input.getClientId())).thenReturn(details);
		input.setScope(Arrays.asList("foo.write"));
		updated.setScope(input.getScope());
		updated.setClientSecret(null);
		ClientDetails result = endpoints.updateClientDetails(input, input.getClientId());
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).updateClientDetails(updated);
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
		Mockito.verify(clientRegistrationService).updateClientSecret(details.getClientId(), "newpassword");

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
		Mockito.verify(clientRegistrationService).updateClientSecret(details.getClientId(), "newpassword");

	}

	@Test
	public void testRemoveClientDetailsAdminCaller() throws Exception {
		Mockito.when(securityContextAccessor.isAdmin()).thenReturn(true);
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(details);
		endpoints.createClientDetails(details);
		ClientDetails result = endpoints.removeClientDetails("foo");
		assertNull(result.getClientSecret());
		Mockito.verify(clientRegistrationService).removeClientDetails("foo");
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void testScopeIsRestrictedByCaller() throws Exception {
		BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
				"uaa.none");
		when(clientDetailsService.loadClientByClientId("caller")).thenReturn(caller);
		endpoints.setSecurityContextAccessor(new StubSecurityContextAccessor() {
			@Override
			public String getClientId() {
				return "caller";
			}
		});
		details.setScope(Arrays.asList("some"));
		endpoints.createClientDetails(details);
	}

	@Test
	public void testValidScopeIsNotRestrictedByCaller() throws Exception {
		BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
				"uaa.none");
		when(clientDetailsService.loadClientByClientId("caller")).thenReturn(caller);
		endpoints.setSecurityContextAccessor(new StubSecurityContextAccessor() {
			@Override
			public String getClientId() {
				return "caller";
			}
		});
		details.setScope(Arrays.asList("none"));
		endpoints.createClientDetails(details);
	}

	@Test
	public void testClientPrefixScopeIsNotRestrictedByClient() throws Exception {
		BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
				"uaa.none");
		when(clientDetailsService.loadClientByClientId("caller")).thenReturn(caller);
		endpoints.setSecurityContextAccessor(new StubSecurityContextAccessor() {
			@Override
			public String getClientId() {
				return "caller";
			}
		});
		details.setScope(Arrays.asList(details.getClientId() + ".read"));
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void testAuthorityIsRestrictedByCaller() throws Exception {
		BaseClientDetails caller = new BaseClientDetails("caller", null, "none", "client_credentials,implicit",
				"uaa.none");
		when(clientDetailsService.loadClientByClientId("caller")).thenReturn(caller);
		endpoints.setSecurityContextAccessor(new StubSecurityContextAccessor() {
			@Override
			public String getClientId() {
				return "caller";
			}
		});
		details.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.some"));
		endpoints.createClientDetails(details);
	}

	@Test
	public void testAuthorityAllowedByCaller() throws Exception {
		BaseClientDetails caller = new BaseClientDetails("caller", null, "uaa.none", "client_credentials,implicit",
				"uaa.none");
		when(clientDetailsService.loadClientByClientId("caller")).thenReturn(caller);
		endpoints.setSecurityContextAccessor(new StubSecurityContextAccessor() {
			@Override
			public String getClientId() {
				return "caller";
			}
		});
		details.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void cannotExpandScope() throws Exception {
		BaseClientDetails caller = new BaseClientDetails();
		caller.setScope(Arrays.asList("none"));
		when(clientDetailsService.loadClientByClientId("caller")).thenReturn(caller);
		details.setAuthorizedGrantTypes(Arrays.asList("implicit"));
		details.setClientSecret("hello");
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void implicitClientWithNonEmptySecretIsRejected() throws Exception {
		details.setAuthorizedGrantTypes(Arrays.asList("implicit"));
		details.setClientSecret("hello");
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void implicitAndAuthorizationCodeClientIsRejected() throws Exception {
		details.setAuthorizedGrantTypes(Arrays.asList("implicit", "authorization_code"));
		details.setClientSecret("hello");
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void implicitAndAuthorizationCodeClientIsRejectedWithNullPassword() throws Exception {
		details.setAuthorizedGrantTypes(Arrays.asList("implicit", "authorization_code"));
		details.setClientSecret(null);
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void implicitAndAuthorizationCodeClientIsRejectedForAdmin() throws Exception {
		endpoints.setSecurityContextAccessor(new StubSecurityContextAccessor() {
			@Override
			public boolean isAdmin() {
				return true;
			}
		});
		details.setAuthorizedGrantTypes(Arrays.asList("implicit", "authorization_code"));
		details.setClientSecret("hello");
		endpoints.createClientDetails(details);
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void nonImplicitClientWithEmptySecretIsRejected() throws Exception {
		details.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
		details.setClientSecret("");
		endpoints.createClientDetails(details);
	}

	@Test
	public void updateNonImplicitClientWithEmptySecretIsOk() throws Exception {
		Mockito.when(securityContextAccessor.isAdmin()).thenReturn(true);
		details.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
		details.setClientSecret(null);
		endpoints.updateClientDetails(details, details.getClientId());
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void updateNonImplicitClientAndMakeItImplicit() throws Exception {
		assertFalse(details.getAuthorizedGrantTypes().contains("implicit"));
		details.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "implicit"));
		details.setClientSecret(null);
		endpoints.updateClientDetails(details, details.getClientId());
	}

	@Test(expected = InvalidClientDetailsException.class)
	public void invalidGrantTypeIsRejected() throws Exception {
		details.setAuthorizedGrantTypes(Arrays.asList("not_a_grant_type"));
		endpoints.createClientDetails(details);
	}

	@Test
	public void testHandleNoSuchClient() throws Exception {
		ResponseEntity<Void> result = endpoints.handleNoSuchClient(new NoSuchClientException("No such client: foo"));
		assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
	}

	@Test
	public void testHandleClientAlreadyExists() throws Exception {
		ResponseEntity<InvalidClientDetailsException> result = endpoints.handleClientAlreadyExists(new ClientAlreadyExistsException(
				"No such client: foo"));
		assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
	}

	@Test
	public void testErrorHandler() throws Exception {
		ResponseEntity<InvalidClientDetailsException> result = endpoints
				.handleInvalidClientDetails(new InvalidClientDetailsException("No such client: foo"));
		assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
		assertEquals(1, endpoints.getErrorCounts().size());
	}

	private static class StubSecurityContextAccessor implements SecurityContextAccessor {

		@Override
		public boolean isClient() {
			return false;
		}

		@Override
		public boolean isUser() {
			return false;
		}

		@Override
		public boolean isAdmin() {
			return false;
		}

		@Override
		public String getUserId() {
			return null;
		}

		@Override
		public String getClientId() {
			return null;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return Collections.emptySet();
		}

	}

}
