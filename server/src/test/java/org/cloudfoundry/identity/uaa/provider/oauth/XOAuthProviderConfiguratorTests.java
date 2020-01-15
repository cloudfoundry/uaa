package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;

class XOAuthProviderConfiguratorTests {

    private OIDCIdentityProviderDefinition oidc;
    private RawXOAuthIdentityProviderDefinition oauth;

    private MockHttpServletRequest request;
    private XOAuthProviderConfigurator configurator;
    private OidcMetadataFetcher oidcMetadataFetcher;

    private OIDCIdentityProviderDefinition config;
    private String discoveryUrl;
    private IdentityProviderProvisioning provisioning;
    private IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider;
    private IdentityProvider<RawXOAuthIdentityProviderDefinition> oauthProvider;

    @BeforeEach
    void setup() throws MalformedURLException {
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
            def.setScopes(Arrays.asList("openid", "password.write"));
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
    void retrieveAll() {
        List<IdentityProvider> activeXOAuthProviders = configurator.retrieveAll(true, IdentityZone.getUaaZoneId());
        assertEquals(2, activeXOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
    }

    @Test
    void retrieveActive() {
        List<IdentityProvider> activeXOAuthProviders = configurator.retrieveActive(IdentityZone.getUaaZoneId());
        assertEquals(2, activeXOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    void retrieve_by_issuer() throws Exception {
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
    void issuer_not_found() {
        String issuer = "https://accounts.google.com";
        reset(provisioning);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oauthProvider, new IdentityProvider<>().setType(LDAP)));
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId()),
                equalTo(String.format("Active provider with issuer[%s] not found", issuer))
        );
    }

    @Test
    void duplicate_issuer_found() throws Exception {
        String issuer = "https://accounts.google.com";
        reset(provisioning);
        when(provisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId()),
                equalTo(String.format("Duplicate providers with issuer[%s] not found", issuer))
        );
    }

    @Test
    void retrieveByOrigin() {
        when(provisioning.retrieveByOrigin(eq(OIDC10), anyString())).thenReturn(oidcProvider);
        when(provisioning.retrieveByOrigin(eq(OAUTH20), anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieveByOrigin(OIDC10, IdentityZone.getUaaZoneId()));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieveByOrigin(OAUTH20, IdentityZone.getUaaZoneId()));
        verify(configurator, never()).overlay(any());
    }

    @Test
    void retrieveById() {
        when(provisioning.retrieve(eq(OIDC10), anyString())).thenReturn(oidcProvider);
        when(provisioning.retrieve(eq(OAUTH20), anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieve(OIDC10, "id"));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieve(OAUTH20, "id"));
        verify(configurator, never()).overlay(any());
    }

    @Test
    void getParameterizedClass() {
        assertEquals(OIDCIdentityProviderDefinition.class, oidc.getParameterizedClass());
        assertEquals(RawXOAuthIdentityProviderDefinition.class, oauth.getParameterizedClass());
    }


    @Test
    void getCompleteAuthorizationURI_includesNonceOnOIDC() {
        String authzUri = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oidc);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    void getCompleteAuthorizationURI_doesNotIncludeNonceOnOAuth() {
        String authzUri = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oauth);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, not(hasKey("nonce")));
    }

    @Test
    void getCompleteAuthorizationURI_withOnlyDiscoveryUrlForOIDCProvider() throws MalformedURLException, OidcMetadataFetchingException {
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
    void getCompleteAuthorizationUri_hasAllRequiredQueryParametersForOidc() {
        String authzUri = configurator.getCompleteAuthorizationURI("alias", UaaUrlUtils.getBaseURL(request), oidc);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();

        assertThat(authzUri, startsWith(oidc.getAuthUrl().toString()));
        assertThat(queryParams, hasEntry("client_id", oidc.getRelyingPartyId()));
        assertThat(queryParams, hasEntry("response_type", "id_token+code"));
        assertThat(queryParams, hasEntry(is("redirect_uri"), containsString("login%2Fcallback%2Falias")));
        assertThat(queryParams, hasEntry("scope", "openid+password.write"));
        assertThat(queryParams, hasEntry(is("state"), not(is(emptyOrNullString()))));
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    void getCompleteAuthorizationUri_hasAllRequiredQueryParametersForOauth() {
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
        assertThat(queryParams, hasEntry(is("state"), not(is(emptyOrNullString()))));
    }

    @Test
    void excludeUnreachableOidcProvider() throws OidcMetadataFetchingException {
        doThrow(new NullPointerException("")).when(oidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        List<IdentityProvider> providers = configurator.retrieveAll(true, IdentityZone.getUaaZoneId());
        assertEquals(1, providers.size());
        assertEquals(oauthProvider.getName(), providers.get(0).getName());
        verify(configurator, times(1)).overlay(eq(config));
    }
}
