/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.client.integration;


import org.cloudfoundry.identity.client.UaaContext;
import org.cloudfoundry.identity.client.UaaContextFactory;
import org.cloudfoundry.identity.client.token.GrantType;
import org.cloudfoundry.identity.client.token.TokenRequest;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ClientAPITokenIntegrationTest {

    public static String uaaURI = "http://localhost:8080/uaa";

    private UaaContextFactory factory;

    @Before
    public void setUp() throws Exception {
        factory =
            UaaContextFactory.factory(new URI(uaaURI))
                .authorizePath("/oauth/authorize")
                .tokenPath("/oauth/token");
    }

    @Test
    public void test_admin_client_token() throws Exception {
        TokenRequest request = factory.tokenRequest()
            .setClientId("admin")
            .setClientSecret("adminsecret")
            .setGrantType(GrantType.CLIENT_CREDENTIALS);

        UaaContext context = factory.authenticate(request);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertFalse(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("uaa.admin"));
    }

    @Test
    public void test_password_token_no_id_token() throws Exception {
        TokenRequest request = factory.tokenRequest()
            .setClientId("cf")
            .setClientSecret("")
            .setGrantType(GrantType.PASSWORD)
            .setUsername("marissa")
            .setPassword("koala");

        UaaContext context = factory.authenticate(request);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));
    }

    @Test
    public void test_password_token_with_id_token() throws Exception {
        TokenRequest request = factory.tokenRequest()
            .withIdToken()
            .setClientId("cf")
            .setClientSecret("")
            .setGrantType(GrantType.PASSWORD)
            .setUsername("marissa")
            .setPassword("koala");

        UaaContext context = factory.authenticate(request);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertTrue(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));
    }


}
