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

import java.util.Arrays;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;

/**
 * @author Dave Syer
 *
 */
public class ClientAdminBootstrapTests {
	
	private ClientAdminBootstrap bootstrap = new ClientAdminBootstrap();
	
	private ClientRegistrationService clientRegistrationService = Mockito.mock(ClientRegistrationService.class);

	@Test
	public void testClientWithOpenIdOnly() throws Exception {
		BaseClientDetails input = new BaseClientDetails("foo", "openid", "openid", "authorization_code", "ROLE_CLIENT");
		BaseClientDetails output = new BaseClientDetails("foo", "none", "openid", "authorization_code", "uaa.none");
		doSimpleTest(input, output);
	}

	@Test
	public void testAuthCodeClientWithCloudController() throws Exception {
		BaseClientDetails client = new BaseClientDetails("foo", "openid,cloud_controller", "openid,read,write", "authorization_code", "ROLE_CLIENT", null);
		BaseClientDetails output = new BaseClientDetails("foo", "none", "openid,cloud_controller.read,cloud_controller.write", "authorization_code", "uaa.none", null);
		doSimpleTest(client, output);
	}

	@Test
	public void testAdminClient() throws Exception {
		BaseClientDetails input = new BaseClientDetails("foo", "clients,tokens", "read,write,password", "client_credentials", "ROLE_ADMIN", null);
		BaseClientDetails output = new BaseClientDetails("foo", "none", "uaa.none", "client_credentials", "clients.read,clients.secret,clients.write,tokens.read,tokens.write,uaa.admin", null);
		doSimpleTest(input, output);
	}
	
	@Test
	public void testCloudController() throws Exception {
		BaseClientDetails input = new BaseClientDetails("foo", "password,scim,tokens", "read,write,password", "client_credentials", "ROLE_CLIENT,ROLE_ADMIN", null);
		BaseClientDetails output = new BaseClientDetails("foo", "none", "uaa.none", "client_credentials", "password.write,scim.read,scim.write,tokens.read,tokens.write,uaa.admin", null);
		doSimpleTest(input, output);
	}
	
	@Test
	public void testLegacySkippedController() throws Exception {
		BaseClientDetails input = new BaseClientDetails("legacy_foo", "password,scim,tokens", "read,write,password", "client_credentials", "ROLE_CLIENT,ROLE_ADMIN", null);
		bootstrap.setClientRegistrationService(clientRegistrationService);
		Mockito.when(clientRegistrationService.listClientDetails()).thenReturn(Arrays.<ClientDetails>asList(input));
		bootstrap.afterPropertiesSet();
		Mockito.verify(clientRegistrationService, Mockito.times(0)).addClientDetails(Mockito.any(ClientDetails.class));		
	}
	
	private void doSimpleTest(BaseClientDetails input, BaseClientDetails output) throws Exception {
		bootstrap.setClientRegistrationService(clientRegistrationService);
		Mockito.when(clientRegistrationService.listClientDetails()).thenReturn(Arrays.<ClientDetails>asList(input));
		bootstrap.afterPropertiesSet();
		Mockito.verify(clientRegistrationService).updateClientDetails(output);
		BaseClientDetails legacy = new BaseClientDetails(input);
		legacy.setClientId("legacy_" + input.getClientId());
		Mockito.verify(clientRegistrationService).addClientDetails(legacy);		
	}

}
