/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;

import java.time.Instant;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.util.TokenValidation.validate;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class TokenValidationTest {

    private final String signature = "KSav5Pfc7rNR1QPPprBudj8rIDqjceRSnxGCaNIziDE";
    private final String content = "eyJqdGkiOiI4YjE0ZjE5My04MjEyLTRhZjItOTkyNy1lM2FlOTAzZjk0YTYiLCJub25jZSI6IjA0ZTJlOTM0MjAwYjRiOWZiZTVkNGU3MGFlMThiYThlIiwic3ViIjoiYTdmMDdiZjYtZTcyMC00NjUyLTg5OTktZTk4MDE4OWNlZjU0Iiwic2NvcGUiOlsiYWNtZS5kZXYiXSwiY2xpZW50X2lkIjoiYXBwIiwiY2lkIjoiYXBwIiwiYXpwIjoiYXBwIiwiZ3JhbnRfdHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsInVzZXJfaWQiOiJhN2YwN2JmNi1lNzIwLTQ2NTItODk5OS1lOTgwMTg5Y2VmNTQiLCJvcmlnaW4iOiJ1YWEiLCJ1c2VyX25hbWUiOiJtYXJpc3NhIiwiZW1haWwiOiJtYXJpc3NhQHRlc3Qub3JnIiwiYXV0aF90aW1lIjoxNDU4OTUzNTU0LCJyZXZfc2lnIjoiZmExYzc4N2QiLCJpYXQiOjE0NTg5NTM5MzIsImV4cCI6MTQ1ODk5NzEzMiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJhcHAiLCJhY21lIl19";
    private final String header = "eyJhbGciOiJIUzI1NiJ9";
    private final String token = header + "." + content + "." + signature;
    /*
          "jti": "8b14f193-8212-4af2-9927-e3ae903f94a6",
          "nonce": "04e2e934200b4b9fbe5d4e70ae18ba8e",
          "sub": "a7f07bf6-e720-4652-8999-e980189cef54",
          "scope": [
            "acme.dev"
          ],
          "client_id": "app",
          "cid": "app",
          "azp": "app",
          "grant_type": "authorization_code",
          "user_id": "a7f07bf6-e720-4652-8999-e980189cef54",
          "origin": "uaa",
          "user_name": "marissa",
          "email": "marissa@test.org",
          "auth_time": 1458953554,
          "rev_sig": "fa1c787d",
          "iat": 1458953932,
          "exp": 1458997132,
          "iss": "http://localhost:8080/uaa/oauth/token",
          "zid": "uaa",
          "aud": [
            "app",
            "acme"
          ]
     */


    private boolean signatureIsValid;
    private final SignatureVerifier verifier = new SignatureVerifier() {
        @Override
        public void verify(byte[] content, byte[] signature) {
            if(!signatureIsValid) throw new InvalidSignatureException("Signature invalid according to test.");
        }

        @Override
        public String algorithm() {
            return "SHA256withRSA";
        }
    };

    private final Instant oneSecondAfterTheTokenExpires = Instant.ofEpochSecond(1458997132 + 1);
    private final Instant oneSecondBeforeTheTokenExpires = Instant.ofEpochSecond(1458997132 - 1);


    @Before
    public void setup() {
        signatureIsValid = true;
    }

    @Test
    public void validateToken() throws Exception {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("app", new BaseClientDetails("app", "acme", "acme.dev", "authorization_code", "")));

        UaaUserDatabase userDb = new MockUaaUserDatabase(u -> u
                .withUsername("marissa")
                .withId("a7f07bf6-e720-4652-8999-e980189cef54")
                .withEmail("marissa@test.org")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("acme.dev"))));

        TokenValidation validation = validate(token)
                .checkSignature(verifier)
                .checkIssuer("http://localhost:8080/uaa/oauth/token")
                .checkClient(clientDetailsService)
                .checkExpiry(oneSecondBeforeTheTokenExpires)
                .checkUser(userDb)
                .checkScopesInclude("acme.dev")
                .checkScopesWithin("acme.dev", "another.scope")
                .checkRevocationSignature("fa1c787d")
                .checkAudience("acme", "app")
                ;

        assertThat(validation.getValidationErrors(), empty());
        assertTrue(validation.isValid());
    }

    @Test
    public void tokenWithInvalidSignature() throws Exception {
        signatureIsValid = false;
        TokenValidation validation = validate(token)
                .checkSignature(verifier);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void invalidJwt() throws Exception {
        TokenValidation validation = validate("invalid_jwt");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void tokenWithInvalidIssuer() throws Exception {
        TokenValidation validation = validate(token)
                .checkIssuer("http://wrong.issuer/");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void emptyBodyJwt() throws Exception {
        TokenValidation validation = validate(header + ".." + signature);
        assertThat(validation.getValidationErrors(), empty());
        assertTrue("Token with no claims is valid after decoding.", validation.isValid());

        assertFalse("Token with no claims fails issuer check.", validation.clone().checkIssuer("http://localhost:8080/uaa/oauth/token").isValid());
        assertFalse("Token with no claims fails expiry check.", validation.clone().checkExpiry(oneSecondBeforeTheTokenExpires).isValid());
    }

    @Test
    public void expiredToken() {
        TokenValidation validation = validate(token)
                .checkExpiry(oneSecondAfterTheTokenExpires);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void nonExistentUser() {
        UaaUserDatabase userDb = new InMemoryUaaUserDatabase(Collections.emptySet());

        TokenValidation validation = validate(token)
                .checkUser(userDb);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void userHadScopeRevoked() {
        UaaUserDatabase userDb = new MockUaaUserDatabase(u -> u
                .withUsername("marissa")
                .withId("a7f07bf6-e720-4652-8999-e980189cef54")
                .withEmail("marissa@test.org")
                .withAuthorities(Collections.singletonList(new SimpleGrantedAuthority("a.different.scope"))));

        TokenValidation validation = validate(token)
                .checkUser(userDb);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void tokenHasInsufficientScope() {
        TokenValidation validation = validate(token)
                .checkScopesInclude("a.different.scope");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InsufficientScopeException.class)));
    }

    @Test
    public void tokenContainsRevokedScope() {
        TokenValidation validation = validate(token)
                .checkScopesWithin("a.different.scope");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void nonExistentClient() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.emptyMap());
        TokenValidation validation = validate(token)
                .checkClient(clientDetailsService);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void clientHasScopeRevoked() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("app", new BaseClientDetails("app", "acme", "a.different.scope", "authorization_code", "")));

        TokenValidation validation = validate(token)
                .checkClient(clientDetailsService);
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void clientRevocationHashChanged() {
        TokenValidation validation = validate(token)
                .checkRevocationSignature("New-Hash");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }

    @Test
    public void incorrectAudience() {
        TokenValidation validation = validate(token)
                .checkAudience("app", "somethingelse");
        assertFalse(validation.isValid());
        assertThat(validation.getValidationErrors(), hasItem(instanceOf(InvalidTokenException.class)));
    }
}
