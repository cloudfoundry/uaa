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
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

public class XOAuthAuthenticationManagerTest {

    private MockRestServiceServer mockUaaServer;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private IdentityProviderProvisioning provisioning;
    private InMemoryUaaUserDatabase userDatabase;
    private XOAuthCodeToken xCodeToken;
    private ApplicationEventPublisher publisher;
    private static final String CODE = "the_code";

    private static final String ORIGIN = "the_origin";
    private static final String ISSUER = "cf-app.com";
    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider;
    private Map<String, Object> claims;
    private HashMap<String, Object> attributeMappings;
    private XOIDCIdentityProviderDefinition config;
    private String rsaSigningKey;
    private RsaSigner signer;
    private Map<String, Object> header;

    @Before
    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
        header = map(
            entry("alg", "HS256"),
            entry("kid", "testKey"),
            entry("typ", "JWT")
        );
    }


    @Before
    public void setUp() throws Exception {
        rsaSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIBOQIBAAJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdpY8Ada9pZfxXz1PZSqv9T\n" +
                "PTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQABAkBoR39y4rw0/QsY3PKQD5xo\n" +
                "hYSZCMCmJUI/sFCuECevIFY4h6q9KBP+4Set96f7Bgs9wJWVvCMx/nJ6guHAjsIB\n" +
                "AiEAywVOoCGIZ2YzARXWYcMRYZ89hxoHh8kZ+QMthRSZieECIQCP/GWQYgyofAQA\n" +
                "BtM8YwThXEV+S3KtuCn4IAQ89gqdGQIgULBASpZpPyc4OEM0nFBKFTGT46EtwwLj\n" +
                "RrvDmLPSPiECICQi9FqIQSUH+vkGvX0qXM8ymT5ZMS7oSaA8aNPj7EYBAiEAx5V3\n" +
                "2JGEulMY3bK1PVGYmtsXF1gq6zbRMoollMCRSMg=\n" +
                "-----END RSA PRIVATE KEY-----";
        signer = new RsaSigner(rsaSigningKey);

        provisioning = mock(JdbcIdentityProviderProvisioning.class);
        userDatabase = new InMemoryUaaUserDatabase(Collections.emptySet());
        publisher = mock(ApplicationEventPublisher.class);
        xoAuthAuthenticationManager = new XOAuthAuthenticationManager(provisioning);
        xoAuthAuthenticationManager.setUserDatabase(userDatabase);
        xoAuthAuthenticationManager.setApplicationEventPublisher(publisher);
        mockUaaServer = MockRestServiceServer.createServer(xoAuthAuthenticationManager.getRestTemplate());
        xCodeToken = new XOAuthCodeToken(CODE, ORIGIN, "http://localhost/callback/the_origin");
        claims = map(
            entry("sub", "12345"),
            entry("preferred_username", "marissa"),
            entry("origin", "uaa"),
            entry("iss", "http://oidc10.identity.cf-app.com/oauth/token"),
            entry("given_name", "Marissa"),
            entry("client_id", "client"),
            entry("aud", Arrays.asList("identity", "another_trusted_client")),
            entry("zid", "uaa"),
            entry("user_id", "12345"),
            entry("azp", "client"),
            entry("scope", Arrays.asList("openid")),
            entry("auth_time", 1458603913),
            entry("phone_number", "1234567890"),
            entry("exp", Instant.now().getEpochSecond() + 3600),
            entry("iat", 1458603913),
            entry("family_name", "Bloggs"),
            entry("jti", "b23fe183-158d-4adc-8aff-65c440bbbee1"),
            entry("email", "marissa@bloggs.com"),
            entry("rev_sig", "3314dc98"),
            entry("cid", "client")
        );

        attributeMappings = new HashMap<>();

        config = new XOIDCIdentityProviderDefinition()
            .setAuthUrl(new URL("http://oidc10.identity.cf-app.com/oauth/authorize"))
            .setTokenUrl(new URL("http://oidc10.identity.cf-app.com/oauth/token"))
            .setShowLinkText(true)
            .setLinkText("My OIDC Provider")
            .setRelyingPartyId("identity")
            .setRelyingPartySecret("identitysecret")
            .setUserInfoUrl(new URL("http://oidc10.identity.cf-app.com/userinfo"))
            .setTokenKey("-----BEGIN PUBLIC KEY-----\n" +
                    "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdp\n" +
                    "Y8Ada9pZfxXz1PZSqv9TPTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQAB\n" +
                    "-----END PUBLIC KEY-----");
    }

    @Test
    public void exchangeExternalCodeForIdToken_andCreateShadowUser() throws Exception {
        mockToken();
        addTheUserOnAuth();

        xoAuthAuthenticationManager.authenticate(xCodeToken);

        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent)userArgumentCaptor.getAllValues().get(0);

        UaaUser uaaUser = event.getUser();
        assertEquals("Marissa",uaaUser.getGivenName());
        assertEquals("Bloggs", uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com", uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("marissa",uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }


    @Test(expected = AccountNotPreCreatedException.class)
    public void doesNotCreateShadowUserAndFailsAuthentication_IfAddShadowUserOnLoginIsFalse() throws Exception {
        config.setAddShadowUserOnLogin(false);
        mockToken();
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidSignature() throws Exception {
        mockToken();

        config.setTokenKey("WRONG_KEY");

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidSignatureAccordingToTokenKeyEndpoint() throws Exception {
        config.setTokenKey(null);
        config.setTokenKeyUrl(new URL("http://oidc10.identity.cf-app.com/token_key"));

        KeyInfo key = new KeyInfo();
        key.setKeyId("wrongKey");
        key.setSigningKey("-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIBOgIBAAJBAJnlBG4lLmUiHslsKDODfd0MqmGZRNUOhn7eO3cKobsFljUKzRQe\n" +
                "GB7LYMjPavnKccm6+jWSXutpzfAc9A9wXG8CAwEAAQJADwwdiseH6cuURw2UQLUy\n" +
                "sVJztmdOG6b375+7IMChX6/cgoF0roCPP0Xr70y1J4TXvFhjcwTgm4RI+AUiIDKw\n" +
                "gQIhAPQHwHzdYG1639Qz/TCHzuai0ItwVC1wlqKpat+CaqdZAiEAoXFyS7249mRu\n" +
                "xtwRAvxKMe+eshHvG2le+ZDrM/pz8QcCIQCzmCDpxGL7L7sbCUgFN23l/11Lwdex\n" +
                "uXKjM9wbsnebwQIgeZIbVovUp74zaQ44xT3EhVwC7ebxXnv3qAkIBMk526sCIDVg\n" +
                "z1jr3KEcaq9zjNJd9sKBkqpkVSqj8Mv+Amq+YjBA\n" +
                "-----END RSA PRIVATE KEY-----");
        VerificationKeyResponse verificationKeyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        String response = JsonUtils.writeValueAsString(verificationKeyResponse);

        mockToken();
        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/token_key"))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidIssuer() throws Exception {
        claims.put("iss", "http://wrong.issuer/");
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectExpiredToken() throws Exception {
        claims.put("exp", Instant.now().getEpochSecond() - 1);
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectWrongAudience() throws Exception {
        claims.put("aud", Arrays.asList("another_client", "a_complete_stranger"));
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void updateShadowUser_IfAlreadyExists() throws MalformedURLException {
        claims.put("scope", Arrays.asList("openid", "some.other.scope", "closedid"));
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();

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

        userDatabase.addUser(existingShadowUser);

        xoAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(2)).publishEvent(userArgumentCaptor.capture());
        assertEquals(2, userArgumentCaptor.getAllValues().size());
        ExternalGroupAuthorizationEvent event = (ExternalGroupAuthorizationEvent)userArgumentCaptor.getAllValues().get(0);

        UaaUser uaaUser = event.getUser();
        assertEquals("Marissa",uaaUser.getGivenName());
        assertEquals("Bloggs",uaaUser.getFamilyName());
        assertEquals("marissa@bloggs.com", uaaUser.getEmail());
        assertEquals("the_origin", uaaUser.getOrigin());
        assertEquals("1234567890", uaaUser.getPhoneNumber());
        assertEquals("marissa", uaaUser.getUsername());
        assertEquals(OriginKeys.UAA, uaaUser.getZoneId());
    }

    @Test
    public void invitedUser_becomesVerifiedOnAccept() throws Exception {
        getInvitedUser();

        claims.remove("preferred_username");
        claims.put("preferred_username", "marissa@bloggs.com");
        mockToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
        mockUaaServer.verify();

        ArgumentCaptor<ApplicationEvent> userArgumentCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        verify(publisher,times(3)).publishEvent(userArgumentCaptor.capture());
        assertEquals(3, userArgumentCaptor.getAllValues().size());
        assertThat(userArgumentCaptor.getAllValues().get(0), instanceOf(InvitedUserAuthenticatedEvent.class));

        RequestContextHolder.resetRequestAttributes();
    }

    private UaaUser getInvitedUser() {
        UaaUser existingShadowUser = new UaaUser(new UaaUserPrototype()
            .withUsername("marissa@bloggs.com")
            .withPassword("")
            .withEmail("marissa@bloggs.com")
            .withGivenName("Marissa_Old")
            .withFamilyName("Bloggs_Old")
            .withId("user-id")
            .withOrigin("the_origin")
            .withZoneId("uaa")
            .withAuthorities(UaaAuthority.USER_AUTHORITIES));

        userDatabase.addUser(existingShadowUser);

        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute("IS_INVITE_ACCEPTANCE", true, RequestAttributes.SCOPE_SESSION);
        attributes.setAttribute("user_id", existingShadowUser.getId(), RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        return existingShadowUser;
    }

    @Test
    public void loginAndValidateSignatureUsingTokenKeyEndpoint() throws Exception {
        config.setTokenKeyUrl(new URL("http://oidc10.identity.cf-app.com/token_key"));
        config.setTokenKey(null);

        KeyInfo key = new KeyInfo();
        key.setKeyId("correctKey");
        key.setSigningKey(rsaSigningKey);
        VerificationKeyResponse verificationKeyResponse = TokenKeyEndpoint.getVerificationKeyResponse(key);
        String response = JsonUtils.writeValueAsString(verificationKeyResponse);

        mockToken();
        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/token_key"))
                .andExpect(header("Authorization", "Basic " + new String(Base64.encodeBase64("identity:identitysecret".getBytes()))))
                .andExpect(header("Accept", "application/json"))
                .andRespond(withStatus(OK).contentType(APPLICATION_JSON).body(response));

        mockToken();

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

        userDatabase.addUser(existingShadowUser);

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void authenticatedUser_hasAuthoritiesFromListOfIDTokenRoles() throws MalformedURLException {
        claims.put("scope", Arrays.asList("openid", "some.other.scope", "closedid"));
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    public void authenticatedUser_hasAuthoritiesFromCommaSeparatedStringOfIDTokenRoles() throws MalformedURLException {
        claims.put("scope", "openid,some.other.scope,closedid");
        testTokenHasAuthoritiesFromIdTokenRoles();
    }

    @Test
    public void authenticatedUser_hasConfigurableUsernameField() throws Exception {
        attributeMappings.put(USER_NAME_ATTRIBUTE_NAME, "username");

        claims.remove("preferred_username");
        claims.put("username", "marissa");
        mockToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));

        assertThat(uaaUser.getUsername(), is("marissa"));
    }

    @Test
    public void getUserWithNullEmail() throws MalformedURLException {
        claims.put("email", null);
        mockToken();
        UaaUser user = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));

        assertEquals("marissa@user.from.the_origin.cf", user.getEmail());
    }

    private XOAuthAuthenticationManager.AuthenticationData getAuthenticationData(XOAuthCodeToken xCodeToken) {
        return xoAuthAuthenticationManager.getExternalAuthenticationDetails(xCodeToken);
    }

    @Test
    public void testGetUserSetsTheRightOrigin() {
        xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));
        assertEquals(ORIGIN, xoAuthAuthenticationManager.getOrigin());

        XOAuthCodeToken otherToken = new XOAuthCodeToken(CODE, "other_origin", "http://localhost/callback/the_origin");
        xoAuthAuthenticationManager.getUser(otherToken, getAuthenticationData(otherToken));
        assertEquals("other_origin", xoAuthAuthenticationManager.getOrigin());
    }

    @Test
    public void testGetUserIssuerOverrideNotUsed() throws Exception {
        mockToken();
        assertNotNull(xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken)));
    }

    @Test
    public void testGetUserIssuerOverrideUsedNoMatch() throws Exception {
        config.setIssuer(ISSUER);
        mockToken();
        try {
            xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));
            fail("InvalidTokenException should have been thrown");
        } catch(InvalidTokenException ex) { }
    }

    @Test
    public void testGetUserIssuerOverrideUsedMatch() throws Exception {
        config.setIssuer(ISSUER);
        claims.remove("iss");
        claims.put("iss", ISSUER);
        mockToken();
        assertNotNull(xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken)));
    }

    @Test
    public void failsIfProviderIsNotOIDCOrOAuth() throws Exception {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(MultitenancyFixture.identityProvider("the_origin", "uaa"));
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test
    public void failsIfProviderIsNotFound() throws Exception {
        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(null);
        Authentication authentication = xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertNull(authentication);
    }

    @Test(expected = HttpServerErrorException.class)
    public void tokenCannotBeFetchedFromCodeBecauseOfServerError() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/oauth/token")).andRespond(withServerError());
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = HttpClientErrorException.class)
    public void tokenCannotBeFetchedFromInvalidCode() throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

        mockUaaServer.expect(requestTo("http://oidc10.identity.cf-app.com/oauth/token")).andRespond(withBadRequest());
        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    private void addTheUserOnAuth() {
        doAnswer(invocation -> {
            Object e = invocation.getArguments()[0];
            if (e instanceof NewUserAuthenticatedEvent) {
                NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) e;
                UaaUser user = event.getUser();
                userDatabase.addUser(user);
            }
            return null;
        }).when(publisher).publishEvent(Matchers.any(ApplicationEvent.class));
    }

    @Test
    public void authenticationContainsAMRClaim_fromExternalOIDCProvider() throws Exception {
        addTheUserOnAuth();
        claims.put("amr", Arrays.asList("mfa", "rba"));
        mockToken();
        UaaAuthentication authentication = (UaaAuthentication)xoAuthAuthenticationManager.authenticate(xCodeToken);
        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("mfa", "rba", "ext"));
    }

    private void mockToken() throws MalformedURLException {
        String idTokenJwt = UaaTokenUtils.constructToken(header, claims, signer);
        identityProvider = getProvider();

        when(provisioning.retrieveByOrigin(eq(ORIGIN), anyString())).thenReturn(identityProvider);

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
        config.setAttributeMappings(attributeMappings);

        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }

    private void testTokenHasAuthoritiesFromIdTokenRoles() throws MalformedURLException {
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        mockToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken, getAuthenticationData(xCodeToken));

        List<String> authorities = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        assertThat(authorities, containsInAnyOrder("openid", "some.other.scope", "closedid"));
    }

}
