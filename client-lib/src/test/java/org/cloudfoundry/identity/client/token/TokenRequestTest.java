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

package org.cloudfoundry.identity.client.token;

import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.util.Arrays;

import static java.util.Collections.EMPTY_LIST;
import static org.cloudfoundry.identity.client.token.GrantType.AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.client.token.GrantType.AUTHORIZATION_CODE_WITH_TOKEN;
import static org.cloudfoundry.identity.client.token.GrantType.CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.client.token.GrantType.FETCH_TOKEN_FROM_CODE;
import static org.cloudfoundry.identity.client.token.GrantType.PASSWORD;
import static org.cloudfoundry.identity.client.token.GrantType.PASSWORD_WITH_PASSCODE;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class TokenRequestTest {

    private TokenRequest request;

    @Before
    public void setUp() throws Exception {
        URI turi = new URI("http://localhost:8080/uaa/oauth/token");
        URI auri = new URI("http://localhost:8080/uaa/oauth/authorize");
        request = new TokenRequest(turi, auri);
    }

    @Test
    public void test_is_client_credentials_grant_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(CLIENT_CREDENTIALS).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertTrue(request.setClientSecret("client_secret").isValid());
    }

    @Test
    public void test_is_password_grant_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(PASSWORD).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertFalse(request.setClientSecret("client_secret").isValid());
        assertFalse(request.setUsername("username").isValid());
        assertTrue(request.setPassword("password").isValid());
    }

    @Test
    public void test_is_password_with_code_grant_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(PASSWORD_WITH_PASSCODE).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertFalse(request.setClientSecret("client_secret").isValid());
        assertFalse(request.setUsername("username").isValid());
        assertTrue(request.setPasscode("passcode").isValid());
    }

    @Test
    public void test_is_auth_code_grant_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(AUTHORIZATION_CODE).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertFalse(request.setClientSecret("client_secret").isValid());
        assertFalse(request.setUsername("username").isValid());
        assertFalse(request.setPassword("password").isValid());
        assertFalse(request.setState("state").isValid());
        assertTrue(request.setRedirectUri(new URI("http://localhost:8080/test")).isValid());
    }

    @Test
    public void test_is_fetch_token_from_code_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(FETCH_TOKEN_FROM_CODE).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertFalse(request.setClientSecret("client_secret").isValid());
        assertFalse(request.setAuthorizationCode("some code").isValid());
        assertTrue(request.setRedirectUri(new URI("http://localhost:8080/test")).isValid());
    }

    @Test
    public void test_is_auth_code_grant_api_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(AUTHORIZATION_CODE_WITH_TOKEN).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertFalse(request.setClientSecret("client_secret").isValid());
        assertFalse(request.setUsername("username").isValid());
        assertFalse(request.setPassword("password").isValid());
        assertFalse(request.setAuthCodeAPIToken("some token").isValid());
        assertFalse(request.setState("state").isValid());
        assertTrue(request.setRedirectUri(new URI("http://localhost:8080/test")).isValid());
    }

    @Test
    public void test_is_saml2_bearer_grant_api_valid() throws Exception {
        assertFalse(request.isValid());
        assertFalse(request.setGrantType(GrantType.SAML2_BEARER).isValid());
        assertFalse(request.setClientId("client_id").isValid());
        assertFalse(request.setClientSecret("client_secret").isValid());
        assertTrue(request.setAuthCodeAPIToken("some token").isValid());
    }

    @Test
    public void test_is_null_function() {
        assertTrue(request.hasAnyNullValues(null));
        assertFalse(request.hasAnyNullValues(EMPTY_LIST));
        assertTrue(request.hasAnyNullValues(Arrays.asList("1", null, "2")));
        assertFalse(request.hasAnyNullValues(Arrays.asList("1", "2", "3")));
    }
}