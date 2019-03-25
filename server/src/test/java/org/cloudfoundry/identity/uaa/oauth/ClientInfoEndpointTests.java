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

package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientInfoEndpoint;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Dave Syer
 *
 */
public class ClientInfoEndpointTests {

    private ClientInfoEndpoint endpoint = new ClientInfoEndpoint();

    private MultitenantClientServices clientDetailsService = Mockito.mock(MultitenantClientServices.class);

    private BaseClientDetails foo = new BaseClientDetails("foo", "none", "read,write", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none");

    {
        foo.setClientSecret("bar");
        foo.setAdditionalInformation(Collections.singletonMap("key", "value"));
        endpoint.setClientDetailsService(clientDetailsService);
    }

    @Test
    public void testClientinfo() {
        Mockito.when(clientDetailsService.loadClientByClientId("foo", "uaa")).thenReturn(foo);
        ClientDetails client = endpoint.clientinfo(new UsernamePasswordAuthenticationToken("foo", "<NONE>"));
        assertEquals("foo", client.getClientId());
        assertNull(client.getClientSecret());
        assertTrue(client.getAdditionalInformation().isEmpty());
    }

}
