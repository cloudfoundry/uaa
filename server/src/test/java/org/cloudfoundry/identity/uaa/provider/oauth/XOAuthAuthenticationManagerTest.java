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
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

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
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_PREFIX;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
    private IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider;
    private Map<String, Object> claims;
    private HashMap<String, Object> attributeMappings;

    @Before
    public void setUp() {
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
    }

    @Test
    public void exchangeExternalCodeForIdToken_andCreateShadowUser() throws Exception {
        getToken();
        doAnswer(invocation -> {
            Object e = invocation.getArguments()[0];
            if (e instanceof NewUserAuthenticatedEvent) {
                NewUserAuthenticatedEvent event = (NewUserAuthenticatedEvent) e;
                UaaUser user = event.getUser();
                userDatabase.addUser(user);
            }
            return null;
        }).when(publisher).publishEvent(Matchers.any(ApplicationEvent.class));

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

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidSignature() throws Exception {
        getToken();

        identityProvider.getConfig().setTokenKey("WRONG_KEY");

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectTokenWithInvalidIssuer() throws Exception {
        claims.put("iss", "http://wrong.issuer/");
        getToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectExpiredToken() throws Exception {
        claims.put("exp", Instant.now().getEpochSecond() - 1);
        getToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test(expected = InvalidTokenException.class)
    public void rejectWrongAudience() throws Exception {
        claims.put("aud", Arrays.asList("another_client", "a_complete_stranger"));
        getToken();

        xoAuthAuthenticationManager.authenticate(xCodeToken);
    }

    @Test
    public void updateShadowUser_IfAlreadyExists() throws MalformedURLException {
        claims.put("scope", Arrays.asList("openid", "some.other.scope", "closedid"));
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        getToken();

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
        attributeMappings.put(USER_NAME_ATTRIBUTE_PREFIX, "username");

        claims.remove("preferred_username");
        claims.put("username", "marissa");
        getToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken);

        assertThat(uaaUser.getUsername(), is("marissa"));
    }

    @Test
    public void getUserWithNullEmail() throws MalformedURLException {
        claims.put("email", null);
        getToken();
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

    private void getToken() throws MalformedURLException {
        String idTokenJwt = constructToken();
        identityProvider = getProvider();

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
        XOIDCIdentityProviderDefinition config = new XOIDCIdentityProviderDefinition()
            .setAuthUrl(new URL("http://oidc10.identity.cf-app.com/oauth/authorize"))
            .setTokenUrl(new URL("http://oidc10.identity.cf-app.com/oauth/token"))
            .setTokenKeyUrl(new URL("http://oidc10.identity.cf-app.com/token_key"))
            .setShowLinkText(true)
            .setLinkText("My OIDC Provider")
            .setRelyingPartyId("identity")
            .setRelyingPartySecret("identitysecret")
            .setUserInfoUrl(new URL("http://oidc10.identity.cf-app.com/userinfo"))
            .setTokenKey("secret");
        config.setAttributeMappings(attributeMappings);

        identityProvider.setConfig(config);
        identityProvider.setOriginKey("puppy");
        return identityProvider;
    }

    private void testTokenHasAuthoritiesFromIdTokenRoles() throws MalformedURLException {
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, "scope");
        getToken();

        UaaUser uaaUser = xoAuthAuthenticationManager.getUser(xCodeToken);

        List<String> authorities = uaaUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        assertThat(authorities, containsInAnyOrder("openid", "some.other.scope", "closedid"));
    }

    private String constructToken() {
        Map<String, Object> header = map(
            entry("alg", "HS256"),
            entry("kid", "testKey"),
            entry("typ", "JWT")
        );
        byte[] headerJson = JsonUtils.writeValueAsBytes(header);
        byte[] claimsJson = JsonUtils.writeValueAsBytes(claims);

        Signer signer = new MacSigner("secret");
        String headerBase64 = Base64.encodeBase64URLSafeString(headerJson);
        String claimsBase64 = Base64.encodeBase64URLSafeString(claimsJson);
        String headerAndClaims = headerBase64 + "." + claimsBase64;
        byte[] signature = signer.sign(headerAndClaims.getBytes());

        String signatureBase64 = Base64.encodeBase64URLSafeString(signature);

        String token = headerAndClaims + "." + signatureBase64;
        return token;
    }
}
