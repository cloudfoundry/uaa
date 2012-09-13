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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * @author Dave Syer
 *
 */
public class ClientInfoEndpointTests {
	
	private ClientInfoEndpoint endpoint = new ClientInfoEndpoint();
	
	private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
	
	private BaseClientDetails foo = new BaseClientDetails("foo", "none", "read,write", "authorization_code", "uaa.none");

	{
		foo.setClientSecret("bar");
		foo.setAdditionalInformation(Collections.singletonMap("key", "value"));
		endpoint.setClientDetailsService(clientDetailsService);
	}
	
	@Test
	public void testClientinfo() {
		Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(foo);
		ClientDetails client = endpoint.clientinfo(new UsernamePasswordAuthenticationToken("foo", "<NONE>"));
		assertEquals("foo", client.getClientId());
		assertNull(client.getClientSecret());
		assertTrue(client.getAdditionalInformation().isEmpty());
	}

}
