/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
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
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.web.client.ResourceAccessException;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class HttpsIntegrationTest {

    public static String uaaURI = "https://login.identity.cf-app.com";

    private UaaContextFactory factory;

    @Rule
    public IsUAAListeningRule uaaListeningRule = new IsUAAListeningRule(uaaURI, false);
    private String clientId;
    private String clientSecret;
    private String redirectUri;

    @Before
    public void setUp() throws Exception {
        redirectUri = "https://uaa.identity.cf-app.com";
        clientId = "xxx";
        clientSecret = "xxx";
        factory =
            UaaContextFactory.factory(new URI(uaaURI))
                .authorizePath("/oauth/authorize")
                .tokenPath("/oauth/token");
    }

    @Test
    public void test_ignore_self_signed_cert_happy_path() throws Exception {
        test_self_signed_cert(true);
    }

    @Test
    public void test_self_signed_cert_should_fail() throws Exception {
        try {
            test_self_signed_cert(false);
            fail("Self signed cert should not pass this test");
        }catch (OAuth2AccessDeniedException x) {
            assertEquals(ResourceAccessException.class, x.getCause().getClass());
        }
    }

    @Test
    @Ignore("Ignored until we have valid client information for acceptance that we can use")
    public void test_fetch_token_from_authorization_code() throws Exception {
        ClientAPITokenIntegrationTest.test_fetch_token_from_authorization_code(factory, uaaURI, false, true, clientId, clientSecret, redirectUri);
    }

    @Test
    @Ignore("Ignored until we have valid client information for acceptance that we can use")
    public void test_fetch_token_from_authorization_code_with_id_token() throws Exception {
        ClientAPITokenIntegrationTest.test_fetch_token_from_authorization_code(factory, uaaURI, true, true, clientId, clientSecret, redirectUri);
    }


    protected void test_self_signed_cert(boolean skipSslValidation) {
        TokenRequest clientCredentials = factory.tokenRequest()
            .setClientId("oauth_showcase_client_credentials")
            .setClientSecret("secret")
            .setGrantType(GrantType.CLIENT_CREDENTIALS)
            .setSkipSslValidation(skipSslValidation);

        UaaContext context = factory.authenticate(clientCredentials);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertFalse(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("uaa.resource"));
    }

}
