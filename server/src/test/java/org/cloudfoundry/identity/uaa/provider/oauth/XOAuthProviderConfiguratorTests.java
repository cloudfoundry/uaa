/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  *******************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.RestTemplateFactory;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static junit.framework.TestCase.assertNotSame;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;


public class XOAuthProviderConfiguratorTests {

    String jsonResponse = "{\n" +
        " \"issuer\": \"https://accounts.google.com\",\n" +
        " \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\",\n" +
        " \"token_endpoint\": \"https://www.googleapis.com/oauth2/v4/token\",\n" +
        " \"userinfo_endpoint\": \"https://www.googleapis.com/oauth2/v3/userinfo\",\n" +
        " \"revocation_endpoint\": \"https://accounts.google.com/o/oauth2/revoke\",\n" +
        " \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\",\n" +
        " \"response_types_supported\": [\n" +
        "  \"code\",\n" +
        "  \"token\",\n" +
        "  \"id_token\",\n" +
        "  \"code token\",\n" +
        "  \"code id_token\",\n" +
        "  \"token id_token\",\n" +
        "  \"code token id_token\",\n" +
        "  \"none\"\n" +
        " ],\n" +
        " \"subject_types_supported\": [\n" +
        "  \"public\"\n" +
        " ],\n" +
        " \"id_token_signing_alg_values_supported\": [\n" +
        "  \"RS256\"\n" +
        " ],\n" +
        " \"scopes_supported\": [\n" +
        "  \"openid\",\n" +
        "  \"email\",\n" +
        "  \"profile\"\n" +
        " ],\n" +
        " \"token_endpoint_auth_methods_supported\": [\n" +
        "  \"client_secret_post\",\n" +
        "  \"client_secret_basic\"\n" +
        " ],\n" +
        " \"claims_supported\": [\n" +
        "  \"aud\",\n" +
        "  \"email\",\n" +
        "  \"email_verified\",\n" +
        "  \"exp\",\n" +
        "  \"family_name\",\n" +
        "  \"given_name\",\n" +
        "  \"iat\",\n" +
        "  \"iss\",\n" +
        "  \"locale\",\n" +
        "  \"name\",\n" +
        "  \"picture\",\n" +
        "  \"sub\"\n" +
        " ],\n" +
        " \"code_challenge_methods_supported\": [\n" +
        "  \"plain\",\n" +
        "  \"S256\"\n" +
        " ]\n" +
        "}";

    private OIDCIdentityProviderDefinition oidc;
    private RawXOAuthIdentityProviderDefinition oauth;


    private String baseExpect = "https://oidc10.uaa-acceptance.cf-app.com/oauth/authorize?client_id=%s&response_type=%s&redirect_uri=%s&scope=%s%s";
    private String redirectUri;
    private MockHttpServletRequest request;
    XOAuthProviderConfigurator configurator;
    private UrlContentCache cache;
    private RestTemplateFactory factory;
    private OIDCIdentityProviderDefinition config;
    private String discoveryUrl;
    private IdentityProviderProvisioning provisioning;
    private IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider;
    private IdentityProvider<RawXOAuthIdentityProviderDefinition> oauthProvider;

    @Before
    public void setup() throws MalformedURLException {
        discoveryUrl = "https://accounts.google.com/.well-known/openid-configuration";
        oidc = new OIDCIdentityProviderDefinition();
        oauth = new RawXOAuthIdentityProviderDefinition();
        request = new MockHttpServletRequest(GET.name(), "/uaa/login");
        request.setContextPath("/uaa");
        request.setServletPath("/login");
        request.setScheme("https");
        request.setServerName("localhost");
        request.setServerPort(8443);

        for (AbstractXOAuthIdentityProviderDefinition def : Arrays.asList(oidc, oauth)) {
            def.setAuthUrl(new URL("https://oidc10.uaa-acceptance.cf-app.com/oauth/authorize"));
            def.setTokenUrl(new URL("https://oidc10.uaa-acceptance.cf-app.com/oauth/token"));
            def.setTokenKeyUrl(new URL("https://oidc10.uaa-acceptance.cf-app.com/token_keys"));
            def.setScopes(Arrays.asList("openid","password.write"));
            def.setRelyingPartyId("clientId");
            if (def == oidc) {
                def.setResponseType("id_token code");
            } else {
                def.setResponseType("code");
            }
        }

        redirectUri = URLEncoder.encode("https://localhost:8443/uaa/login/callback/alias");
        provisioning = mock(IdentityProviderProvisioning.class);
        cache = mock(UrlContentCache.class);
        when(cache.getUrlContent(anyString(), anyObject())).thenReturn(jsonResponse.getBytes());
        factory = mock(RestTemplateFactory.class);
        configurator = spy(new XOAuthProviderConfigurator(provisioning, cache, factory));

        config = new OIDCIdentityProviderDefinition();
        String discoveryUrl = "https://accounts.google.com/.well-known/openid-configuration";
        config.setDiscoveryUrl(new URL(discoveryUrl));
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.setStoreCustomAttributes(true);
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setResponseType("id_token");
        List<String> requestedScopes = new ArrayList<>();
        requestedScopes.add("openid");
        requestedScopes.add("cloud_controller.read");
        config.setScopes(requestedScopes);

        oidcProvider = new IdentityProvider<>();
        oidcProvider.setType(OIDC10);
        oidcProvider.setConfig(config);
        oidcProvider.setOriginKey(OIDC10);
        oauthProvider = new IdentityProvider<>();
        oauthProvider.setType(OAUTH20);
        oauthProvider.setConfig(new RawXOAuthIdentityProviderDefinition());
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));

    }

    @Test
    public void retrieveAll() {
        List<IdentityProvider> activeXOAuthProviders = configurator.retrieveAll(true, IdentityZone.getUaa().getId());
        assertEquals(2, activeXOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
    }

    @Test
    public void retrieveActive() {
        List<IdentityProvider> activeXOAuthProviders = configurator.retrieveActive(IdentityZone.getUaa().getId());
        assertEquals(2, activeXOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    public void retrieveByOrigin() {
        when(provisioning.retrieveByOrigin(eq(OIDC10),anyString())).thenReturn(oidcProvider);
        when(provisioning.retrieveByOrigin(eq(OAUTH20),anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieveByOrigin(OIDC10, IdentityZone.getUaa().getId()));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieveByOrigin(OAUTH20, IdentityZone.getUaa().getId()));
        verify(configurator, never()).overlay(anyObject());
    }

    @Test
    public void retrieveById() {
        when(provisioning.retrieve(eq(OIDC10))).thenReturn(oidcProvider);
        when(provisioning.retrieve(eq(OAUTH20))).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieve(OIDC10));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieve(OAUTH20));
        verify(configurator, never()).overlay(anyObject());
    }

    @Test
    public void getParameterizedClass() throws Exception {
        assertEquals(OIDCIdentityProviderDefinition.class, oidc.getParameterizedClass());
        assertEquals(RawXOAuthIdentityProviderDefinition.class, oauth.getParameterizedClass());
    }

    @Test
    public void overlay_noDiscoveryUrl() {
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        verifyZeroInteractions(cache);
        assertSame(definition, configurator.overlay(definition));
    }

    @Test
    public void overlay_withOverrideValues() throws MalformedURLException {
        String urlBase = "http://localhost:8080/uaa";


        config.setSkipSslValidation(true);
        //values from URL
        config.setAuthUrl(new URL(urlBase + "/oauth/authorize"));
        config.setTokenUrl(new URL(urlBase + "/oauth/token"));
        config.setTokenKeyUrl(new URL(urlBase + "/token_key"));
        config.setUserInfoUrl(new URL(urlBase + "/userinfo"));
        config.setIssuer(urlBase + "/oauth/token");

        OIDCIdentityProviderDefinition overlay = configurator.overlay(config);

        assertNotSame(config, overlay);
        assertEquals(config, overlay);
        verify(cache).getUrlContent(eq(discoveryUrl), any());
        verify(factory).getRestTemplate(eq(true));
    }

    @Test
    public void overlay_withoutOverrideValues() throws MalformedURLException {
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();

        config.setDiscoveryUrl(new URL(discoveryUrl));
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.setStoreCustomAttributes(true);
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setResponseType("id_token");
        List<String> requestedScopes = new ArrayList<>();
        requestedScopes.add("openid");
        requestedScopes.add("cloud_controller.read");
        config.setScopes(requestedScopes);
        config.setSkipSslValidation(false);

        OIDCIdentityProviderDefinition overlay = configurator.overlay(config);

        assertNotSame(config, overlay);
        assertNotEquals(config, overlay);
        assertEquals(new URL("https://accounts.google.com/o/oauth2/v2/auth"), overlay.getAuthUrl());
        assertEquals(new URL("https://www.googleapis.com/oauth2/v3/userinfo"), overlay.getUserInfoUrl());
        assertEquals("https://accounts.google.com", overlay.getIssuer());
        assertEquals(new URL("https://www.googleapis.com/oauth2/v4/token"), overlay.getTokenUrl());
        assertEquals(new URL("https://www.googleapis.com/oauth2/v3/certs"), overlay.getTokenKeyUrl());

        verify(cache).getUrlContent(any(), any());
        verify(factory).getRestTemplate(eq(false));
    }


    @Test
    public void getCompleteAuthorizationURI_includesNonceOnOIDC() throws UnsupportedEncodingException {
        String expected = String.format(baseExpect, oidc.getRelyingPartyId(), URLEncoder.encode("id_token code"), redirectUri, URLEncoder.encode("openid password.write"), "&nonce=");
        assertThat(configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oidc), startsWith(expected));
    }

    @Test
    public void getCompleteAuthorizationURI_doesNotIncludeNonceOnOAuth() throws UnsupportedEncodingException {
        String expected = String.format(baseExpect, oauth.getRelyingPartyId(), URLEncoder.encode("code"), redirectUri, URLEncoder.encode("openid password.write"), "");
        assertEquals(configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oauth), expected);
    }

    @Test
    public void excludeUnreachableOidcProvider() {
        when(cache.getUrlContent(anyString(), anyObject())).thenReturn(null);

        List<IdentityProvider> providers = configurator.retrieveAll(true, IdentityZone.getUaa().getId());
        assertEquals(1, providers.size());
        assertEquals(oauthProvider.getName(), providers.get(0).getName());
        verify(configurator, times(1)).overlay(eq(config));
    }
}
