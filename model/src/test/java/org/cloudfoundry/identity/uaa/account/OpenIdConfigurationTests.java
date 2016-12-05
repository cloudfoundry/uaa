/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.account;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class OpenIdConfigurationTests {

    private OpenIdConfiguration defaultConfig;

    @Before
    public void setup() {
        defaultConfig = new OpenIdConfiguration("/uaa", "issuer");
    }

    @Test
    public void testDefaultClaims() {
        assertEquals("issuer", defaultConfig.getIssuer());
        assertEquals("/uaa/oauth/authorize", defaultConfig.getAuthUrl());
        assertEquals("/uaa/oauth/token", defaultConfig.getTokenUrl());
        assertArrayEquals(new String[]{"client_secret_basic"}, defaultConfig.getTokenAMR());
        assertArrayEquals(new String[]{"SHA256withRSA", "HMACSHA256"}, defaultConfig.getTokenEndpointAuthSigningValues());
        assertEquals("/uaa/userInfo", defaultConfig.getUserInfoUrl());
        assertArrayEquals(new String[]{"openid", "profile", "email", "phone"}, defaultConfig.getScopes());
        assertArrayEquals(new String[]{"code", "code id_token", "id_token", "token id_token"}, defaultConfig.getResponseTypes());
        assertArrayEquals(new String[]{"SHA256withRSA", "HMACSHA256"}, defaultConfig.getIdTokenSigningAlgValues());
        assertArrayEquals(new String[]{"none"}, defaultConfig.getRequestObjectSigningAlgValues());
        assertArrayEquals(new String[]{"normal"}, defaultConfig.getClaimTypesSupported());
        assertArrayEquals(
            new String[]{
                "sub", "user_name", "origin", "iss", "auth_time",
                "amr", "acr", "client_id", "aud", "zid", "grant_type",
                "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig",
                "cid", "given_name", "family_name", "phone_number", "email"},
            defaultConfig.getClaimsSupported()
        );
        assertFalse(defaultConfig.isClaimsParameterSupported());
        assertEquals("http://docs.cloudfoundry.org/api/uaa/", defaultConfig.getServiceDocumentation());
        assertArrayEquals(new String[]{"en-US"}, defaultConfig.getUiLocalesSupported());
    }

}