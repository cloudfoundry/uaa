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

package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OidcAuthenticationFlow;
import org.cloudfoundry.identity.uaa.provider.XOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.response.MockRestResponseCreators;

import java.net.URL;

import static junit.framework.TestCase.assertEquals;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

public class XOAuthAuthenticationManagerTest {

    private MockRestServiceServer mockUaaServer;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private IdentityProviderProvisioning provisioning;

    private String idTokenJwt = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3RLZXkiLCJ0eXAiOiJKV1QifQ." +
            "eyJzdWIiOiIxMjM0NSIsInVzZXJfbmFtZSI6Im1hcmlzc2EiLCJvcmlnaW4iOiJ1YWEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiZ2l2ZW5fbmFtZSI6Ik1hcmlzc2EiLCJjbGllbnRfaWQiOiJjbGllbnQiLCJhdWQiOlsiY2xpZW50Il0sInppZCI6InVhYSIsInVzZXJfaWQiOiIxMjM0NSIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJhdXRoX3RpbWUiOjE0NTg2MDM5MTMsInBob25lX251bWJlciI6IjEyMzQ1Njc4OTAiLCJleHAiOjE0NTg2NDcxMTMsImlhdCI6MTQ1ODYwMzkxMywiZmFtaWx5X25hbWUiOiJCbG9nZ3MiLCJqdGkiOiJiMjNmZTE4My0xNThkLTRhZGMtOGFmZi02NWM0NDBiYmJlZTEiLCJlbWFpbCI6Im1hcmlzc2FAYmxvZ2dzLmNvbSIsInJldl9zaWciOiIzMzE0ZGM5OCIsImNpZCI6ImNsaWVudCJ9" +
            ".UCl_8gJMlZWBACYefXCRkZqDi72gZ6g-HJCvvNcQUFc";

    @Before
    public void setUp() {
        provisioning = Mockito.mock(JdbcIdentityProviderProvisioning.class);
        xoAuthAuthenticationManager = new XOAuthAuthenticationManager(provisioning);
        mockUaaServer = MockRestServiceServer.createServer(xoAuthAuthenticationManager.getRestTemplate());
    }

    @Test
    public void authenticatesWithExternalCode() throws Exception {
        String origin = "the_origin";
        String code = "the_code";
        XOAuthCodeToken xCodeToken = new XOAuthCodeToken(code, origin, "http://localhost/callback/the_origin");

        IdentityProvider<XOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        XOAuthIdentityProviderDefinition<OidcAuthenticationFlow> config = new XOAuthIdentityProviderDefinition<>();
        config.setAuthUrl(new URL("http://oidc10.identity.cf-app.com/oauth/authorize"));
        config.setTokenUrl(new URL("http://oidc10.identity.cf-app.com/oauth/token"));
        config.setTokenKeyUrl(new URL("http://oidc10.identity.cf-app.com/token_key"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setAuthenticationFlow(new OidcAuthenticationFlow().setUserInfoUrl(new URL("http://oidc10.identity.cf-app.com/userinfo")));
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");

        Mockito.when(provisioning.retrieveByOrigin(eq(origin), anyString())).thenReturn(identityProvider);

        CompositeAccessToken compositeAccessToken = new CompositeAccessToken("accessToken");
        compositeAccessToken.setIdTokenValue(idTokenJwt);
        String response = JsonUtils.writeValueAsString(compositeAccessToken);
        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/oauth/token")).andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
        UserInfoResponse userInfoResponse = new UserInfoResponse();
        userInfoResponse.setEmail("marissa@bloggs.com");
        userInfoResponse.setFamilyName("Bloggs");
        userInfoResponse.setGivenName("Marissa");
        userInfoResponse.setUsername("marissa");
        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/userinfo")).andExpect(header("Authorization", "bearer " + idTokenJwt)).andRespond(withStatus(OK).body(JsonUtils.writeValueAsString(userInfoResponse)).contentType(APPLICATION_JSON));

        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);

        mockUaaServer.verify();

        assertThat(authentication, notNullValue());
        assertThat(authentication, instanceOf(UaaAuthentication.class));

        UaaAuthentication uaaAuthentication = (UaaAuthentication) authentication;

        assertEquals("marissa", uaaAuthentication.getName());
        assertThat(uaaAuthentication.getPrincipal(), instanceOf(UaaPrincipal.class));

        UaaPrincipal principal = uaaAuthentication.getPrincipal();
        assertEquals("marissa@bloggs.com", principal.getEmail());
        assertEquals("the_origin", principal.getOrigin());
        assertEquals(OriginKeys.UAA, principal.getZoneId());
    }

    @Test
    public void failsIfProviderIsNotOIDCOrOAuth() throws Exception {


    }
}