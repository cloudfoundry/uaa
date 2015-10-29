package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.Origin;
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
public class Oauth2RefreshTokenAssertions extends AbstractOAuth2TokenAssertions<Oauth2RefreshTokenAssertions> {

    public static final String CLIENT_ID = "client";
    public static final String CANNOT_READ_TOKEN_CLAIMS = "Cannot read token claims";
    public static final String DELETE = "delete";
    private int refreshTokenValidity = 60 * 60 * 24 * 30;


    public Oauth2RefreshTokenAssertions(String username, List<String> resourceIds, List<String> requestedAuthScopes) {
        super(username, requestedAuthScopes, resourceIds);
    }

    @Override
    public void executeAssertions(OAuth2AccessToken token, SignerProvider signer) {
        assertNotNull(token);

        Jwt refreshTokenJwt = JwtHelper.decodeAndVerify(token.getRefreshToken().getValue(), signer.getVerifier());
        assertNotNull(refreshTokenJwt);
        Map<String, Object> refreshTokenClaims;
        try {
            refreshTokenClaims = JsonUtils.readValue(refreshTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException(CANNOT_READ_TOKEN_CLAIMS, e);
        }

        this.executeCommonAssertions(refreshTokenClaims);

        assertTrue(((String) refreshTokenClaims.get(Claims.JTI)).length() > 0);
        assertTrue(((Integer) refreshTokenClaims.get(Claims.IAT)) > 0);
        assertTrue(((Integer) refreshTokenClaims.get(Claims.EXP)) > 0);
        assertTrue(((Integer) refreshTokenClaims.get(Claims.EXP)) - ((Integer) refreshTokenClaims.get(Claims.IAT)) == refreshTokenValidity);
    }

    public static Oauth2RefreshTokenAssertions refreshTokenAssertions(String username, List<String> resourceIds, List<String> requestedAuthScopes) {
        return new Oauth2RefreshTokenAssertions(username, resourceIds, requestedAuthScopes);
    }

    public Oauth2RefreshTokenAssertions withRefreshTokenValidity(int refreshTokenValidity) {
        this.refreshTokenValidity = refreshTokenValidity;
        return this;
    }
}
