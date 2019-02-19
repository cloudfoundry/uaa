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

import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static junit.framework.TestCase.assertNotSame;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.*;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpMethod.GET;


public class XOAuthProviderConfiguratorTests {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private OIDCIdentityProviderDefinition oidc;
    private RawXOAuthIdentityProviderDefinition oauth;

    private MockHttpServletRequest request;
    XOAuthProviderConfigurator configurator;
    private OidcMetadataFetcher oidcMetadataFetcher;

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
            def.setAuthUrl(new URL("http://oidc10.random-made-up-url.com/oauth/authorize"));
            def.setTokenUrl(new URL("http://oidc10.random-made-up-url.com/oauth/token"));
            def.setTokenKeyUrl(new URL("http://oidc10.random-made-up-url.com/token_keys"));
            def.setScopes(Arrays.asList("openid","password.write"));
            def.setRelyingPartyId("clientId");
            if (def == oidc) {
                def.setResponseType("id_token code");
            } else {
                def.setResponseType("code");
            }
        }

        provisioning = mock(IdentityProviderProvisioning.class);
        oidcMetadataFetcher = mock(OidcMetadataFetcher.class);

        configurator = spy(new XOAuthProviderConfigurator(provisioning, oidcMetadataFetcher));

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
        List<IdentityProvider> activeXOAuthProviders = configurator.retrieveAll(true, IdentityZone.getUaaZoneId());
        assertEquals(2, activeXOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
    }

    @Test
    public void retrieveActive() {
        List<IdentityProvider> activeXOAuthProviders = configurator.retrieveActive(IdentityZone.getUaaZoneId());
        assertEquals(2, activeXOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    public void retrieve_by_issuer() throws Exception {
        String issuer = "https://accounts.google.com";
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityProvider<OIDCIdentityProviderDefinition> activeXOAuthProvider = configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId());

        assertEquals(issuer, activeXOAuthProvider.getConfig().getIssuer());
        verify(configurator, times(1)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    public void issuer_not_found() throws Exception {
        String issuer = "https://accounts.google.com";
        exception.expect(IncorrectResultSizeDataAccessException.class);
        exception.expectMessage(String.format("Active provider with issuer[%s] not found", issuer));
        reset(provisioning);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oauthProvider, new IdentityProvider<>().setType(LDAP)));
        IdentityProvider<OIDCIdentityProviderDefinition> activeXOAuthProvider = configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId());
        assertEquals(issuer, activeXOAuthProvider.getConfig().getIssuer());
        verify(configurator, times(0)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    public void duplicate_issuer_found() throws Exception {
        String issuer = "https://accounts.google.com";
        exception.expect(IncorrectResultSizeDataAccessException.class);
        exception.expectMessage(String.format("Duplicate providers with issuer[%s] not found", issuer));
        reset(provisioning);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityProvider<OIDCIdentityProviderDefinition> activeXOAuthProvider = configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId());

        assertEquals(issuer, activeXOAuthProvider.getConfig().getIssuer());
        verify(configurator, times(2)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    public void retrieveByOrigin() {
        when(provisioning.retrieveByOrigin(eq(OIDC10),anyString())).thenReturn(oidcProvider);
        when(provisioning.retrieveByOrigin(eq(OAUTH20),anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieveByOrigin(OIDC10, IdentityZone.getUaaZoneId()));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieveByOrigin(OAUTH20, IdentityZone.getUaaZoneId()));
        verify(configurator, never()).overlay(any());
    }

    @Test
    public void retrieveById() {
        when(provisioning.retrieve(eq(OIDC10), anyString())).thenReturn(oidcProvider);
        when(provisioning.retrieve(eq(OAUTH20), anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieve(OIDC10, "id"));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieve(OAUTH20, "id"));
        verify(configurator, never()).overlay(any());
    }

    @Test
    public void getParameterizedClass() throws Exception {
        assertEquals(OIDCIdentityProviderDefinition.class, oidc.getParameterizedClass());
        assertEquals(RawXOAuthIdentityProviderDefinition.class, oauth.getParameterizedClass());
    }


    @Test
    public void getCompleteAuthorizationURI_includesNonceOnOIDC() throws UnsupportedEncodingException {
        String authzUri = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oidc);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    public void getCompleteAuthorizationURI_doesNotIncludeNonceOnOAuth() throws UnsupportedEncodingException {
        String authzUri = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oauth);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, not(hasKey("nonce")));
    }

    @Test
    public void getCompleteAuthorizationURI_withOnlyDiscoveryUrlForOIDCProvider() throws MalformedURLException, OidcMetadataFetchingException {
        oidc.setDiscoveryUrl(new URL(discoveryUrl));
        oidc.setAuthUrl(null);
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setAuthUrl(new URL("https://accounts.google.com/o/oauth2/v2/auth"));
            return null;
        }).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        String authorizationURI = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oidc);

        assertThat(authorizationURI, Matchers.startsWith("https://accounts.google.com/o/oauth2/v2/auth"));
        verify(configurator).overlay(oidc);
    }

    @Test
    public void getCompleteAuthorizationUri_hasAllRequiredQueryParametersForOidc() {
        String authzUri = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oidc);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();

        assertThat(authzUri, startsWith(oidc.getAuthUrl().toString()));
        assertThat(queryParams, hasEntry("client_id", oidc.getRelyingPartyId()));
        assertThat(queryParams, hasEntry("response_type", "id_token+code"));
        assertThat(queryParams, hasEntry(is("redirect_uri"), containsString("login%2Fcallback%2Falias")));
        assertThat(queryParams, hasEntry("scope", "openid+password.write"));
        assertThat(queryParams, hasEntry(is("state"), not(isEmptyOrNullString())));
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    public void getCompleteAuthorizationUri_hasAllRequiredQueryParametersForOauth() {
        String authzUri = configurator.getCompleteAuthorizationURI(
                "alias",
                UaaUrlUtils.getBaseURL(request),
                oauth
        );

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();

        assertThat(authzUri, startsWith(oidc.getAuthUrl().toString()));
        assertThat(queryParams, hasEntry("client_id", oidc.getRelyingPartyId()));
        assertThat(queryParams, hasEntry("response_type", "code"));
        assertThat(queryParams, hasEntry(is("redirect_uri"), containsString("login%2Fcallback%2Falias")));
        assertThat(queryParams, hasEntry("scope", "openid+password.write"));
        assertThat(queryParams, hasEntry(is("state"), not(isEmptyOrNullString())));
    }

    @Test
    public void excludeUnreachableOidcProvider() throws OidcMetadataFetchingException {
        doThrow(new NullPointerException("")).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        List<IdentityProvider> providers = configurator.retrieveAll(true, IdentityZone.getUaaZoneId());
        assertEquals(1, providers.size());
        assertEquals(oauthProvider.getName(), providers.get(0).getName());
        verify(configurator, times(1)).overlay(eq(config));
    }
}
