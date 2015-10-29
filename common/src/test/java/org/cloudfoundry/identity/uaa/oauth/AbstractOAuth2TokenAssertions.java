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
public abstract class AbstractOAuth2TokenAssertions<T> implements OAuth2TokenAssertion {

    public static final String CLIENT_ID = "client";
    public static final String DELETE = "delete";
    protected String username;
    protected List<String> resourceIds;
    protected List<String> expectedScopes;

    protected String issuerUri = "http://localhost:8080/uaa/oauth/token";

    protected AbstractOAuth2TokenAssertions(String username, List<String> expectedScopes, List<String> resourceIds) {
        this.username = username;
        this.expectedScopes = expectedScopes;
        this.resourceIds = resourceIds;
    }

    public T withIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
        return (T)this;
    }

    public void executeCommonAssertions(Map<String, Object> claims) {
        assertEquals(issuerUri, claims.get(Claims.ISS));
        assertEquals(username, claims.get(Claims.USER_NAME));
        assertEquals(CLIENT_ID, claims.get(Claims.CLIENT_ID));
        assertNotNull(claims.get(Claims.SUB));
        assertEquals(resourceIds, claims.get(Claims.AUD));
        assertEquals(Origin.UAA, claims.get(Claims.ORIGIN));
        assertNotNull("token revocation signature must be present.", claims.get(Claims.REVOCATION_SIGNATURE));
    }
}
