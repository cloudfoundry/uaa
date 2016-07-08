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
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.cloudfoundry.identity.client.integration.ClientIntegrationTestUtilities.UAA_URI;
import static org.cloudfoundry.identity.client.token.GrantType.AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.client.token.GrantType.AUTHORIZATION_CODE_WITH_TOKEN;
import static org.cloudfoundry.identity.client.token.GrantType.FETCH_TOKEN_FROM_CODE;
import static org.cloudfoundry.identity.client.token.GrantType.PASSWORD;
import static org.cloudfoundry.identity.client.token.GrantType.PASSWORD_WITH_PASSCODE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ClientAPITokenIntegrationTest {

    public static String uaaURI = UAA_URI;

    private UaaContextFactory factory;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Rule
    public IsUAAListeningRule uaaListeningRule = new IsUAAListeningRule(uaaURI, false);

    @Before
    public void setUp() throws Exception {
        factory =
            UaaContextFactory.factory(new URI(uaaURI))
                .authorizePath("/oauth/authorize")
                .tokenPath("/oauth/token");
    }

    @Test
    public void test_admin_client_token() throws Exception {
        TokenRequest clientCredentials = factory.tokenRequest()
            .setClientId("admin")
            .setClientSecret("adminsecret")
            .setGrantType(GrantType.CLIENT_CREDENTIALS);

        UaaContext context = factory.authenticate(clientCredentials);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertFalse(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("uaa.admin"));
    }

    @Test
    public void test_password_token_without_id_token() throws Exception {
        UaaContext context = retrievePasswordToken(null);
        assertTrue(context.getToken().getScope().contains("openid"));
    }

    protected UaaContext retrievePasswordToken(Collection<String> scopes) {
        TokenRequest passwordGrant = factory.tokenRequest()
            .setClientId("cf")
            .setClientSecret("")
            .setGrantType(PASSWORD)
            .setUsername("marissa")
            .setPassword("koala")
            .setScopes(scopes);
        UaaContext context = factory.authenticate(passwordGrant);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        return context;
    }

    @Test
    public void test_password_token_with_id_token() throws Exception {
        TokenRequest passwordGrant = factory.tokenRequest()
            .setClientId("cf")
            .setClientSecret("")
            .setGrantType(PASSWORD)
            .setUsername("marissa")
            .setPassword("koala")
            .withIdToken()
            .setScopes(Arrays.asList("openid"));
        UaaContext context = factory.authenticate(passwordGrant);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertTrue(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
    }

    protected void performPasswordGrant(String clientId,
                                        String clientSecret,
                                        GrantType grantType,
                                        String username,
                                        String password) {
        TokenRequest passwordGrant = factory.tokenRequest()
            .withIdToken()
            .setClientId(clientId)
            .setClientSecret(clientSecret)
            .setGrantType(grantType)
            .setUsername(username);
        switch (grantType) {
            case PASSWORD:
                passwordGrant.setPassword(password);
                break;
            case PASSWORD_WITH_PASSCODE:
                passwordGrant.setPasscode(password);
                break;
            default:
                throw new IllegalArgumentException("Invalid grant:"+grantType);
        }

        UaaContext context = factory.authenticate(passwordGrant);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertTrue(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));
    }

    @Test
    public void test_password_token_with_passcode() throws Exception {
        HttpHeaders headers = ClientIntegrationTestUtilities.performFormLogin(uaaURI, "marissa", "koala");
        String passcode = ClientIntegrationTestUtilities.getPasscode(uaaURI, headers);
        performPasswordGrant("cf",
                             "",
                             PASSWORD_WITH_PASSCODE,
                             "marissa",
                             passcode);
    }

    @Test
    public void test_fetch_token_from_authorization_code() throws Exception {
        test_fetch_token_from_authorization_code(factory, uaaURI, false, false, "login", "loginsecret", "http://localhost/redirect");
    }

    @Test
    public void test_fetch_token_from_authorization_code_with_id_token() throws Exception {
        test_fetch_token_from_authorization_code(factory, uaaURI, true, false, "login", "loginsecret", "http://localhost/redirect");
    }

    public static void test_fetch_token_from_authorization_code(UaaContextFactory factory,
                                                                String uaaURI,
                                                                boolean idToken,
                                                                boolean skipSslValidation,
                                                                String clientId,
                                                                String clientSecret,
                                                                String redirectUri) throws Exception {
        HttpHeaders headers = ClientIntegrationTestUtilities.performFormLogin(uaaURI, "marissa", "koala");
        String code = ClientIntegrationTestUtilities.getAuthorizationCode(
            factory.getAuthorizeUri().toString(),
            clientId,
            redirectUri,
            headers
        );
        TokenRequest fetchTokenRequest = factory.tokenRequest()
            .setGrantType(FETCH_TOKEN_FROM_CODE)
            .setRedirectUri(new URI(redirectUri))
            .setClientId(clientId)
            .setClientSecret(clientSecret)
            .setAuthorizationCode(code);
        if (idToken) {
            fetchTokenRequest.withIdToken();
        }
        if (skipSslValidation) {
            fetchTokenRequest.setSkipSslValidation(true);
        }

        UaaContext context = factory.authenticate(fetchTokenRequest);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertEquals(idToken, context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));

    }


    @Test
    @Ignore("test_auth_code_token_with_id_token ignored - No UI/browser implementation yet") //until we have decided if we want to be able to do this without a UI
    public void test_auth_code_token_with_id_token() throws Exception {
        TokenRequest authorizationCode = factory.tokenRequest()
            .withIdToken()
            .setGrantType(AUTHORIZATION_CODE)
            .setRedirectUri(new URI("http://localhost/redirect"))
            .setState(generator.generate())
            .setScopes(Collections.singleton("openid"))
            .setClientId("app")
            .setClientSecret("appclientsecret")
            .setUsername("marissa")
            .setPassword("koala");
        UaaContext context = factory.authenticate(authorizationCode);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));
    }

    @Test
    @Ignore("test_auth_code_token_without_id_token ignred - No UI/browser implementation yet") //until we have decided if we want to be able to do this without a UI
    public void test_auth_code_token_without_id_token() throws Exception {
        TokenRequest authorizationCode = factory.tokenRequest()
            .setGrantType(AUTHORIZATION_CODE)
            .setRedirectUri(new URI("http://localhost/redirect"))
            .setState(generator.generate())
            .setScopes(Collections.singleton("openid"))
            .setClientId("app")
            .setClientSecret("appclientsecret")
            .setUsername("marissa")
            .setPassword("koala");
        UaaContext context = factory.authenticate(authorizationCode);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        assertFalse(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));
    }

    @Test
    public void test_auth_code_token_using_api() throws Exception {
        UaaContext passwordContext = retrievePasswordToken(Arrays.asList("uaa.user"));
        assertTrue(passwordContext.getToken().getScope().contains("uaa.user"));
        TokenRequest authorizationCode = factory.tokenRequest()
            .setGrantType(AUTHORIZATION_CODE_WITH_TOKEN)
            .setRedirectUri(new URI("http://localhost:8080/app/"))
            .setState(generator.generate())
            .setClientId("app")
            .setClientSecret("appclientsecret")
            .setScopes(Arrays.asList("openid"))
            .setAuthCodeAPIToken(passwordContext.getToken().getValue());
        UaaContext context = factory.authenticate(authorizationCode);
        assertNotNull(context);
        assertTrue(context.hasAccessToken());
        //we receive an id_token because we request 'openid' explicitly
        assertTrue(context.hasIdToken());
        assertTrue(context.hasRefreshToken());
        assertTrue(context.getToken().getScope().contains("openid"));
    }

}
