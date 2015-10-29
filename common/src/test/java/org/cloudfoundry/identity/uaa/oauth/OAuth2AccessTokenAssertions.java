package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.oauth.token.SignerProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

public class OAuth2AccessTokenAssertions extends AbstractOAuth2TokenAssertions<OAuth2AccessTokenAssertions> {

    public static final String CLIENT_ID = "client";
    public static final String CANNOT_READ_TOKEN_CLAIMS = "Cannot read token claims";
    public static final String DELETE = "delete";
    private String email;
    private int accessTokenValidity = 60 * 60 * 12;

    private OAuth2AccessTokenAssertions(String username, String email, List<String> expectedScopes, List<String> resourceIds) {
        super(username, expectedScopes, resourceIds);
        this.email = email;

    }

    @Override
    public void executeAssertions(OAuth2AccessToken accessToken, SignerProvider signer) {
        Jwt tokenJwt = JwtHelper.decodeAndVerify(accessToken.getValue(), signer.getVerifier());
        assertNotNull(tokenJwt);
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        this.executeCommonAssertions(claims);

        assertEquals(CLIENT_ID, claims.get(Claims.CID));
        assertNotNull(claims.get(Claims.USER_ID));
        assertEquals(email, claims.get(Claims.EMAIL));
        assertEquals(expectedScopes,claims.get(Claims.SCOPE));
        assertTrue(((String) claims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT))  == accessTokenValidity);
    }

    public static OAuth2AccessTokenAssertions accessTokenAssertions(String username, String email, List<String> expectedScopes, List<String> resourceIds) {
        return new OAuth2AccessTokenAssertions(username, email, expectedScopes, resourceIds);
    }

    public OAuth2AccessTokenAssertions withAccessTokenValidity(int accessTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
        return this;
    }

}
