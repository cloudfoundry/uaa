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

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.yaml.snakeyaml.Yaml;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class ClientAdminBootstrapTests {

	private ClientAdminBootstrap bootstrap;

	private ClientRegistrationService clientRegistrationService;

	@Before
	public void setUp() {
		bootstrap = new ClientAdminBootstrap();
		clientRegistrationService = mock(ClientRegistrationService.class);
		bootstrap.setClientRegistrationService(clientRegistrationService);
	}

	@Test
	public void testSimpleAddClient() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("id", "foo");
		map.put("secret", "bar");
		map.put("scope", "openid");
		map.put("authorized-grant-types", "authorization_code");
		map.put("authorities", "uaa.none");
		BaseClientDetails output = new BaseClientDetails("foo", "none", "openid", "authorization_code,refresh_token",
				"uaa.none");
		output.setClientSecret("bar");
		doSimpleTest(map, output);
	}

	@Test
	public void testSimpleAddClientWithAutoApprove() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("id", "foo");
		map.put("secret", "bar");
		map.put("scope", "openid");
		map.put("authorized-grant-types", "authorization_code");
		map.put("authorities", "uaa.none");
		BaseClientDetails output = new BaseClientDetails("foo", "none", "openid", "authorization_code,refresh_token",
				"uaa.none");
		output.setClientSecret("bar");
		bootstrap.setAutoApproveClients(Arrays.asList("foo"));
		when(clientRegistrationService.listClientDetails()).thenReturn(Collections.<ClientDetails> emptyList())
				.thenReturn(Collections.<ClientDetails> singletonList(output));
		bootstrap.setClients(Collections.singletonMap((String) map.get("id"), map));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService).addClientDetails(output);
		BaseClientDetails updated = new BaseClientDetails(output);
		updated.setAdditionalInformation(Collections.singletonMap("autoapprove", true));
		verify(clientRegistrationService).updateClientDetails(updated);
	}

	@Test
	public void testOverrideClient() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("secret", "bar");
		map.put("override", true);
		bootstrap.setClients(Collections.singletonMap("foo", map));
		doThrow(new ClientAlreadyExistsException("Planned")).when(clientRegistrationService).addClientDetails(
				any(ClientDetails.class));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService, times(1)).addClientDetails(any(ClientDetails.class));
		verify(clientRegistrationService, times(1)).updateClientDetails(any(ClientDetails.class));
		verify(clientRegistrationService, times(1)).updateClientSecret("foo", "bar");
	}

	@Test
	public void testOverrideClientByDefault() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("secret", "bar");
		bootstrap.setClients(Collections.singletonMap("foo", map));
		doThrow(new ClientAlreadyExistsException("Planned")).when(clientRegistrationService).addClientDetails(
				any(ClientDetails.class));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService, times(1)).addClientDetails(any(ClientDetails.class));
		verify(clientRegistrationService, times(1)).updateClientDetails(any(ClientDetails.class));
		verify(clientRegistrationService, times(1)).updateClientSecret("foo", "bar");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void testOverrideClientWithYaml() throws Exception {
		@SuppressWarnings("rawtypes")
		Map fooClient = new Yaml().loadAs("id: foo\noverride: true\nsecret: bar\n"
				+ "access-token-validity: 100", Map.class);
		@SuppressWarnings("rawtypes")
		Map barClient = new Yaml().loadAs("id: bar\noverride: true\nsecret: bar\n"
				+ "access-token-validity: 100", Map.class);
		@SuppressWarnings("rawtypes")
		Map clients = new HashMap();
		clients.put("foo", fooClient);
		clients.put("bar", barClient);
		bootstrap.setClients(clients);
		doThrow(new ClientAlreadyExistsException("Planned")).when(clientRegistrationService).addClientDetails(
				any(ClientDetails.class));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService, times(2)).addClientDetails(any(ClientDetails.class));
		verify(clientRegistrationService, times(2)).updateClientDetails(any(ClientDetails.class));
		verify(clientRegistrationService, times(1)).updateClientSecret("foo", "bar");
		verify(clientRegistrationService, times(1)).updateClientSecret("bar", "bar");
	}

	@Test
	public void testHttpsUrlIsAddedIfNotPresent() throws Exception {
		bootstrap.setDomain("bar.com");
		BaseClientDetails input = new BaseClientDetails("foo", "password,scim,tokens", "read,write,password",
				"client_credentials", "uaa.none", "http://foo.bar.com/spam");
		when(clientRegistrationService.listClientDetails()).thenReturn(Arrays.<ClientDetails> asList(input));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService, times(1)).updateClientDetails(any(ClientDetails.class));
	}

	@Test
	public void testHttpsUrlIsNotAddedIfAlreadyPresent() throws Exception {
		bootstrap.setDomain("bar.com");
		BaseClientDetails input = new BaseClientDetails("foo", "password,scim,tokens", "read,write,password",
				"client_credentials", "uaa.none", "http://foo.bar.com,https://foo.bar.com");
		when(clientRegistrationService.listClientDetails()).thenReturn(Arrays.<ClientDetails> asList(input));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService, times(1)).updateClientDetails(any(ClientDetails.class));
	}

	private void doSimpleTest(Map<String, Object> map, BaseClientDetails output) throws Exception {
		when(clientRegistrationService.listClientDetails()).thenReturn(Collections.<ClientDetails> emptyList());
		bootstrap.setClients(Collections.singletonMap((String) map.get("id"), map));
		bootstrap.afterPropertiesSet();
		verify(clientRegistrationService).addClientDetails(output);
	}

}
