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

import org.apache.commons.codec.binary.Base64;

import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.AccessDeniedException;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

public class XOAuthAuthenticationManagerTest {

    private MockRestServiceServer mockUaaServer;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private IdentityProviderProvisioning provisioning;
    private UaaUserDatabase userDatabase;
    private XOAuthCodeToken xCodeToken;
    private ApplicationEventPublisher publisher;
    private static final String CODE = "the_code";

    private static final String ORIGIN = "the_origin";
    private String idTokenJwt = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3RLZXkiLCJ0eXAiOiJKV1QifQ." +
            "eyJzdWIiOiIxMjM0NSIsInVzZXJfbmFtZSI6Im1hcmlzc2EiLCJvcmlnaW4iOiJ1YWEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiZ2l2ZW5fbmFtZSI6Ik1hcmlzc2EiLCJjbGllbnRfaWQiOiJjbGllbnQiLCJhdWQiOlsiY2xpZW50Il0sInppZCI6InVhYSIsInVzZXJfaWQiOiIxMjM0NSIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJhdXRoX3RpbWUiOjE0NTg2MDM5MTMsInBob25lX251bWJlciI6IjEyMzQ1Njc4OTAiLCJleHAiOjE0NTg2NDcxMTMsImlhdCI6MTQ1ODYwMzkxMywiZmFtaWx5X25hbWUiOiJCbG9nZ3MiLCJqdGkiOiJiMjNmZTE4My0xNThkLTRhZGMtOGFmZi02NWM0NDBiYmJlZTEiLCJlbWFpbCI6Im1hcmlzc2FAYmxvZ2dzLmNvbSIsInJldl9zaWciOiIzMzE0ZGM5OCIsImNpZCI6ImNsaWVudCJ9" +
            ".UCl_8gJMlZWBACYefXCRkZqDi72gZ6g-HJCvvNcQUFc";

    @Before
    public void setUp() {
        provisioning = mock(JdbcIdentityProviderProvisioning.class);
        userDatabase = mock(UaaUserDatabase.class);
        publisher = Mockito.mock(ApplicationEventPublisher.class);
        xoAuthAuthenticationManager = new XOAuthAuthenticationManager(provisioning);
        xoAuthAuthenticationManager.setUserDatabase(userDatabase);
        xoAuthAuthenticationManager.setApplicationEventPublisher(publisher);
        mockUaaServer = MockRestServiceServer.createServer(xoAuthAuthenticationManager.getRestTemplate());
        xCodeToken = new XOAuthCodeToken(CODE, ORIGIN, "http://localhost/callback/the_origin");
    }

    @Test
    public void exchangeExternalCodeForIdToken_andCreateShadowUser() throws Exception {
        getToken(idTokenJwt);
        when(userDatabase.retrieveUserByEmail(anyString(), anyString())).thenReturn(null);

        UaaUser shadowUser = new UaaUser(new UaaUserPrototype()
                                            .withUsername("marissa")
                                            .withPassword("")
                                            .withEmail("marissa@bloggs.com")
                                            .withGivenName("Marissa")
                                            .withFamilyName("Bloggs")
                                            .withId("user-id")
                                            .withAuthorities(UaaAuthority.USER_AUTHORITIES));
        when(userDatabase.retrieveUserByName(anyString(), anyString())).thenAnswer((new Answer() {
            private int count = 0;

            public Object answer(InvocationOnMock invocation) {
                if (count == 0) {
                    count++;
                    return null;
                    }
                return shadowUser;
                }
            }));
        when(userDatabase.retrieveUserById("user-id")).thenReturn(shadowUser);

        xoAuthAuthenticationManager.authenticate(xCodeToken);

        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);

        UaaUser uaaUser = event.getUser();
        assertEquals("Marissa",uaaUser.getGivenName());
        assertEquals("Bloggs",uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com",uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("marissa",uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }

    @Test
    public void updateShadowUser_IfAlreadyExists() throws MalformedURLException {
        UaaUser existingShadowUser = new UaaUser(new UaaUserPrototype()
            .withUsername("marissa")
            .withPassword("")
            .withEmail("marissa_old@bloggs.com")
            .withGivenName("Marissa_Old")
            .withFamilyName("Bloggs_Old")
            .withId("user-id")
            .withOrigin("the_origin")
            .withZoneId("uaa")
            .withAuthorities(UaaAuthority.USER_AUTHORITIES));

        UaaUser updatedShadowUser = new UaaUser(new UaaUserPrototype()
            .withUsername("marissa")
            .withPassword("")
            .withEmail("marissa@bloggs.com")
            .withGivenName("Marissa")
            .withFamilyName("Bloggs")
            .withId("user-id")
            .withAuthorities(UaaAuthority.USER_AUTHORITIES));

        when(userDatabase.retrieveUserByName(anyString(), anyString())).thenReturn(existingShadowUser);
        when(userDatabase.retrieveUserById("user-id")).thenReturn(updatedShadowUser);

        getToken(idTokenJwt);

        xoAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2, userArgumentCaptor.getAllValues().size());
        ExternalGroupAuthorizationEvent event = (ExternalGroupAuthorizationEvent)userArgumentCaptor.getAllValues().get(0);

        UaaUser uaaUser = event.getUser();
        assertEquals(updatedShadowUser.getGivenName(),uaaUser.getGivenName());
        assertEquals(updatedShadowUser.getFamilyName(),uaaUser.getFamilyName());
        assertEquals(updatedShadowUser.getEmail(), uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("marissa", uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }

    @Test
    public void getUserWithNullEmail() throws MalformedURLException {
        String tokenWithNullEmail = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRlc3RLZXkiLCJ0eXAiOiJKV1QifQ." +
            "eyJzdWIiOiIxMjM0NSIsInVzZXJfbmFtZSI6Im1hcmlzc2EiLCJvcmlnaW4iOiJ1YWEiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiZ2l2ZW5fbmFtZSI6Ik1hcmlzc2EiLCJjbGllbnRfaWQiOiJjbGllbnQiLCJhdWQiOlsiY2xpZW50Il0sInppZCI6InVhYSIsInVzZXJfaWQiOiIxMjM0NSIsImF6cCI6ImNsaWVudCIsInNjb3BlIjpbIm9wZW5pZCJdLCJhdXRoX3RpbWUiOjE0NTg2MDM5MTMsInBob25lX251bWJlciI6IjEyMzQ1Njc4OTAiLCJleHAiOjE0NTg2NDcxMTMsImlhdCI6MTQ1ODYwMzkxMywiZmFtaWx5X25hbWUiOiJCbG9nZ3MiLCJqdGkiOiJiMjNmZTE4My0xNThkLTRhZGMtOGFmZi02NWM0NDBiYmJlZTEiLCJyZXZfc2lnIjoiMzMxNGRjOTgiLCJjaWQiOiJjbGllbnQifQ." +
            "MQHRqX5eembDLNAKhYZccrWAN85YLOQrbRp5OLpFuLs";

        getToken(tokenWithNullEmail);
        UaaUser user = xoAuthAuthenticationManager.getUser(xCodeToken);

        assertEquals("marissa@user.from.the_origin.cf", user.getEmail());
    }

    @Test
    public void testGetUserSetsTheRightOrigin() {
        xoAuthAuthenticationManager.getUser(xCodeToken);
        assertEquals(ORIGIN, xoAuthAuthenticationManager.getOrigin());

        XOAuthCodeToken otherToken = new XOAuthCodeToken(CODE, "other_origin", "http://localhost/callback/the_origin");
        xoAuthAuthenticationManager.getUser(otherToken);
        assertEquals("other_origin", xoAuthAuthenticationManager.getOrigin());
    }

    @Test
    public void failsIfProviderIsNotOIDCOrOAuth() throws Exception {
        Mockito.when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(MultitenancyFixture.identityProvider("the_origin", "uaa"));
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    public void failsIfProviderIsNotFound() throws Exception {
        Mockito.when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(null);
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test(expected = HttpServerErrorException.class)
    public void tokenCannotBeFetchedFromCodeBecauseOfServerError() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        Mockito.when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/oauth/token")).andRespond(withServerError());
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = HttpClientErrorException.class)
    public void tokenCannotBeFetchedFromInvalidCode() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        Mockito.when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/oauth/token")).andRespond(withBadRequest());
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    private void getToken(String idTokenJwt) throws MalformedURLException {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        Mockito.when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        CompositeAccessToken compositeAccessToken = new CompositeAccessToken("accessToken");
        compositeAccessToken.setIdTokenValue(idTokenJwt);
        String response = JsonUtils.writeValueAsString(compositeAccessToken);
        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/oauth/token"))
            .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
            .andExpect(header("Accept", "application/json"))
            .andExpect(content().string(containsString("grant_type=authorization_code")))
            .andExpect(content().string(containsString("code=the_code")))
            .andExpect(content().string(containsString("redirect_uri=http%3A%2F%2Flocalhost%2Fcallback%2Fthe_origin")))
            .andExpect(content().string(containsString(("response_type=id_token"))))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));
    }

    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> getProvider() throws MalformedURLException {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName("my oidc provider");
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        XOIDCIdentityProviderDefinition config = new XOIDCIdentityProviderDefinition();
        config.setAuthUrl(new URL("http://oidc10.identity.cf-app.com/oauth/authorize"));
        config.setTokenUrl(new URL("http://oidc10.identity.cf-app.com/oauth/token"));
        config.setTokenKeyUrl(new URL("http://oidc10.identity.cf-app.com/token_key"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setUserInfoUrl(new URL("http://oidc10.identity.cf-app.com/userinfo"));
        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }
}
