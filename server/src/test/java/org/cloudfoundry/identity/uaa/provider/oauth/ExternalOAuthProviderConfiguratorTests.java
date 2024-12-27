package org.cloudfoundry.identity.uaa.provider.oauth;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.UaaRandomStringUtil;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toSet;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class ExternalOAuthProviderConfiguratorTests {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR =
            new AlphanumericRandomValueStringGenerator(6);

    private OIDCIdentityProviderDefinition oidc;
    private RawExternalOAuthIdentityProviderDefinition oauth;

    private ExternalOAuthProviderConfigurator configurator;
    @Mock
    private OidcMetadataFetcher mockOidcMetadataFetcher;
    @Mock
    private IdentityProviderProvisioning mockIdentityProviderProvisioning;
    @Mock
    private UaaRandomStringUtil mockUaaRandomStringUtil;
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private IdentityZoneManager identityZoneManager;

    private OIDCIdentityProviderDefinition config;
    private IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider;
    private IdentityProvider<RawExternalOAuthIdentityProviderDefinition> oauthProvider;

    private MockHttpServletRequest mockHttpServletRequest;

    @BeforeEach
    void setup() throws MalformedURLException {
        oidc = new OIDCIdentityProviderDefinition();
        oauth = new RawExternalOAuthIdentityProviderDefinition();

        for (AbstractExternalOAuthIdentityProviderDefinition def : Arrays.asList(oidc, oauth)) {
            def.setAuthUrl(new URL("http://oidc10.random-made-up-url.com/oauth/authorize"));
            def.setTokenUrl(new URL("http://oidc10.random-made-up-url.com/oauth/token"));
            def.setTokenKeyUrl(new URL("http://oidc10.random-made-up-url.com/token_keys"));
            def.setScopes(Arrays.asList("openid", "password.write"));
            def.setRelyingPartyId("clientId");
            def.setRelyingPartySecret("clientSecret");
        }
        oidc.setResponseType("id_token code");
        oidc.setAdditionalAuthzParameters(Map.of("token_format", "jwt"));
        oauth.setResponseType("code");

        configurator = spy(new ExternalOAuthProviderConfigurator(
                mockIdentityProviderProvisioning,
                mockOidcMetadataFetcher,
                mockUaaRandomStringUtil,
                identityZoneProvisioning,
                identityZoneManager));

        config = new OIDCIdentityProviderDefinition();
        config.setDiscoveryUrl(new URL("https://accounts.google.com/.well-known/openid-configuration"));
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.addAttributeMapping("user.attribute." + "the_client_id", "cid");
        config.setStoreCustomAttributes(true);
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setResponseType("id_token");
        config.setScopes(List.of("openid", "cloud_controller.read"));

        oidcProvider = new IdentityProvider<>();
        oidcProvider.setType(OIDC10);
        oidcProvider.setConfig(config);
        oidcProvider.setOriginKey(OIDC10);
        oauthProvider = new IdentityProvider<>();
        oauthProvider.setType(OAUTH20);
        oauthProvider.setConfig(new RawExternalOAuthIdentityProviderDefinition());

        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletRequest.setRequestURI("https://localhost:8443/uaa");
    }

    @Test
    void retrieveAll() {
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));

        List<IdentityProvider> activeExternalOAuthProviders = configurator.retrieveAll(true, IdentityZone.getUaaZoneId());
        assertEquals(2, activeExternalOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
    }

    @Test
    void retrieveActive() {
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));

        List<IdentityProvider> activeExternalOAuthProviders = configurator.retrieveActive(IdentityZone.getUaaZoneId());
        assertEquals(2, activeExternalOAuthProviders.size());
        verify(configurator, times(1)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @ParameterizedTest
    @MethodSource
    void retrieveActiveByTypes_ShouldReturnEmptyListWhenNeitherOidcNorOAuthInTypes(final String[] types) {
        final String zoneId = RandomStringUtils.randomAlphanumeric(8);

        /* arrange one active IdP per type being present in the zone
         * -> however, they should not be returned since the types don't match */
        final String originKeyPrefix = RandomStringUtils.randomAlphanumeric(8) + "-";
        final List<IdentityProvider> idps = new HashSet<>(Arrays.asList(types)).stream()
                .map(type -> {
                    final IdentityProvider idp = new IdentityProvider<>();
                    final String originKey = "%s%s".formatted(originKeyPrefix, type);
                    idp.setOriginKey(originKey);
                    idp.setId(originKey);
                    idp.setType(type);
                    idp.setActive(true);
                    return idp;
                }).toList();
        lenient().when(mockIdentityProviderProvisioning.retrieveActiveByTypes(zoneId, types)).thenReturn(idps);

        assertTrue(configurator.retrieveActiveByTypes(zoneId, types).isEmpty());
    }

    private static Stream<Arguments> retrieveActiveByTypes_ShouldReturnEmptyListWhenNeitherOidcNorOAuthInTypes() {
        return Stream.of(
                new String[]{SAML},
                new String[]{SAML, LDAP},
                new String[]{},
                (Object) new String[]{UAA, LDAP, LDAP} // contains duplicates
        ).map(Arguments::of);
    }

    @Test
    void retrieveActiveByNullType() {
        assertEquals(0, configurator.retrieveActiveByTypes(IdentityZone.getUaaZoneId(), null).size());
    }

    @ParameterizedTest
    @MethodSource
    void retrieveActiveByTypes(final String[] types) throws OidcMetadataFetchingException {
        final String zoneId = RandomStringUtils.randomAlphanumeric(8);

        // eliminate duplicates
        final Set<String> typesAsSet = new HashSet<>(Arrays.asList(types));
        final boolean inputContainsOidc = typesAsSet.contains(OIDC10);
        final boolean inputContainsOauth = typesAsSet.contains(OAUTH20);

        // arrange one active IdP of every type in "oauth2.0" and "oidc1.0" exists in the zone
        final String originKeyPrefix = RandomStringUtils.randomAlphanumeric(8) + "-";
        final List<IdentityProvider> idps = Stream.of(OIDC10, OAUTH20)
                .filter(type -> !OIDC10.equals(type) || inputContainsOidc)
                .filter(type -> !OAUTH20.equals(type) || inputContainsOauth)
                .map(type -> {
                    final IdentityProvider idp = new IdentityProvider<>();
                    final String originKey = "%s%s".formatted(originKeyPrefix, type);
                    idp.setOriginKey(originKey);
                    idp.setId(originKey);
                    idp.setType(type);
                    if (OIDC10.equals(type)) {
                        idp.setConfig(new OIDCIdentityProviderDefinition());
                    }
                    idp.setActive(true);
                    return idp;
                }).toList();
        if (inputContainsOidc && inputContainsOauth) {
            lenient().when(mockIdentityProviderProvisioning.retrieveActiveByTypes(zoneId, OIDC10, OAUTH20))
                    .thenReturn(idps);
            lenient().when(mockIdentityProviderProvisioning.retrieveActiveByTypes(zoneId, OAUTH20, OIDC10))
                    .thenReturn(idps);
        } else if (inputContainsOidc) {
            when(mockIdentityProviderProvisioning.retrieveActiveByTypes(zoneId, OIDC10)).thenReturn(idps);
        } else if (inputContainsOauth) {
            when(mockIdentityProviderProvisioning.retrieveActiveByTypes(zoneId, OAUTH20)).thenReturn(idps);
        }

        final List<IdentityProvider> result = configurator.retrieveActiveByTypes(zoneId, types);

        /* the result should contain only IdPs of type "oauth2.0" and "oidc1.0" and only if the corresponding type
         * was part of the input types */
        final int expectedSize = (inputContainsOauth ? 1 : 0) + (inputContainsOidc ? 1 : 0);
        assertEquals(expectedSize, result.size());

        final Set<String> typesInResult = result.stream().map(IdentityProvider::getType).collect(toSet());
        assertEquals(expectedSize, typesInResult.size());
        assertEquals(inputContainsOauth, typesInResult.contains(OAUTH20));
        assertEquals(inputContainsOidc, typesInResult.contains(OIDC10));

        if (inputContainsOidc) {
            verify(mockOidcMetadataFetcher, times(1)).fetchMetadataAndUpdateDefinition(any());
        }
    }

    private static Stream<Arguments> retrieveActiveByTypes() {
        return Stream.of(
                new String[]{OIDC10, OAUTH20},
                new String[]{OIDC10},
                new String[]{OAUTH20},
                new String[]{OIDC10, OIDC10, OAUTH20}, // contains duplicates
                new String[]{OIDC10, LDAP, SAML}, // ldap and saml should be ignored
                new String[]{OIDC10, OIDC10, LDAP, SAML}, // ldap and saml should be ignored
                (Object) new String[]{OIDC10, OIDC10, OAUTH20, LDAP, SAML} // ldap and saml should be ignored
        ).map(Arguments::of);
    }

    @Test
    void retrieve_by_issuer() throws Exception {
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));

        String issuer = "https://accounts.google.com";
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(IdentityZone.getUaa());
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(mockOidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityProvider<OIDCIdentityProviderDefinition> activeExternalOAuthProvider = configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId());

        assertEquals(issuer, activeExternalOAuthProvider.getConfig().getIssuer());
        verify(configurator, times(1)).overlay(eq(config));
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    void retrieve_by_issuer_search() throws Exception {
        when(mockIdentityProviderProvisioning.retrieveByExternId(anyString(), anyString(), anyString())).thenReturn(oidcProvider);

        String issuer = "https://accounts.google.com";
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(mockOidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityProvider<OIDCIdentityProviderDefinition> activeExternalOAuthProvider = configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId());

        assertEquals(issuer, activeExternalOAuthProvider.getConfig().getIssuer());
        verify(configurator, times(1)).overlay(config);
        verify(configurator, times(1)).retrieveByExternId(anyString(), anyString(), anyString());
    }

    @Test
    void retrieve_by_issuer_legacy() throws Exception {
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));
        when(mockIdentityProviderProvisioning.retrieveByExternId(anyString(), anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        String issuer = "https://accounts.google.com";
        IdentityZone extraZone = IdentityZone.getUaa();
        extraZone.setId("customer");
        extraZone.setSubdomain("customer");
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(identityZoneProvisioning.retrieve("customer")).thenReturn(extraZone);
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(mockOidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        IdentityProvider<OIDCIdentityProviderDefinition> activeExternalOAuthProvider = configurator.retrieveByIssuer(issuer, "customer");

        assertEquals(issuer, activeExternalOAuthProvider.getConfig().getIssuer());
        verify(configurator, times(1)).overlay(config);
        verify(configurator, times(1)).retrieveByExternId(anyString(), anyString(), anyString());
        verify(configurator, times(1)).retrieveAll(eq(true), anyString());
    }

    @Test
    void retrieve_by_issuer_not_found_error() {
        when(mockIdentityProviderProvisioning.retrieveByExternId(anyString(), anyString(), anyString())).thenThrow(new EmptyResultDataAccessException(1));

        String issuer = "https://accounts.google.com";
        IdentityZone extraZone = IdentityZone.getUaa();
        extraZone.getConfig().getUserConfig().setAllowOriginLoop(false);
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(extraZone);
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId()),
                startsWith("No provider with unique issuer[%s] found".formatted(issuer))
        );
    }

    @Test
    void retrieve_by_issuer_null_error() {
        when(mockIdentityProviderProvisioning.retrieveByExternId(anyString(), anyString(), anyString())).thenReturn(null);

        String issuer = "https://accounts.google.com";
        IdentityZone extraZone = IdentityZone.getUaa();
        extraZone.getConfig().getUserConfig().setAllowOriginLoop(false);
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(extraZone);
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId()),
                startsWith("Active provider with unique issuer[%s] not found".formatted(issuer))
        );
    }

    @Test
    void issuer_not_found() {
        String issuer = "https://accounts.google.com";
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oauthProvider, new IdentityProvider<>().setType(LDAP)));
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(IdentityZone.getUaa());
        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId()),
                equalTo("Active provider with issuer[%s] not found".formatted(issuer))
        );
    }

    @Test
    void duplicate_issuer_found() throws Exception {
        String issuer = "https://accounts.google.com";
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(IdentityZone.getUaa());
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setIssuer(issuer);
            return null;
        }).when(mockOidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        assertThrowsWithMessageThat(
                IncorrectResultSizeDataAccessException.class,
                () -> configurator.retrieveByIssuer(issuer, IdentityZone.getUaaZoneId()),
                equalTo("Duplicate providers with issuer[%s] not found".formatted(issuer))
        );
    }

    @Test
    void retrieveByOrigin() {
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq(OIDC10), anyString())).thenReturn(oidcProvider);
        when(mockIdentityProviderProvisioning.retrieveByOrigin(eq(OAUTH20), anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieveByOrigin(OIDC10, IdentityZone.getUaaZoneId()));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieveByOrigin(OAUTH20, IdentityZone.getUaaZoneId()));
        verify(configurator, never()).overlay(any());
    }

    @Test
    void retrieveById() {
        when(mockIdentityProviderProvisioning.retrieve(eq(OIDC10), anyString())).thenReturn(oidcProvider);
        when(mockIdentityProviderProvisioning.retrieve(eq(OAUTH20), anyString())).thenReturn(oauthProvider);

        assertNotNull(configurator.retrieve(OIDC10, "id"));
        verify(configurator, times(1)).overlay(eq(config));

        reset(configurator);
        assertNotNull(configurator.retrieve(OAUTH20, "id"));
        verify(configurator, never()).overlay(any());
    }

    @Test
    void getParameterizedClass() {
        assertEquals(OIDCIdentityProviderDefinition.class, oidc.getParameterizedClass());
        assertEquals(RawExternalOAuthIdentityProviderDefinition.class, oauth.getParameterizedClass());
    }

    @Test
    void getIdpAuthenticationUrl_includesNonceOnOIDC() {
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authzUri = configurator.getIdpAuthenticationUrl(oidc, "alias", mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    void getIdpAuthenticationUrl_doesNotIncludeNonceOnOAuth() {
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authzUri = configurator.getIdpAuthenticationUrl(oauth, "alias", mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, not(hasKey("nonce")));
    }

    @Test
    void getIdpAuthenticationUrl_includesPkceOnPublicOIDC() {
        oidc.setRelyingPartySecret(null); // public client means no secret
        oidc.setPkce(false);
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authzUri = configurator.getIdpAuthenticationUrl(oidc, "alias", mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, hasKey("code_challenge"));
        assertThat(queryParams, hasKey("code_challenge_method"));
    }

    @Test
    void getIdpAuthenticationUrl_includesPkce() {
        oauth.setRelyingPartySecret(null);
        oauth.setPkce(true);
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authzUri = configurator.getIdpAuthenticationUrl(oauth, "alias", mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, hasKey("code_challenge"));
        assertThat(queryParams, hasKey("code_challenge_method"));
    }

    @Test
    void oidcIdPPkceEqual() throws CloneNotSupportedException {
        OIDCIdentityProviderDefinition oidc1 = (OIDCIdentityProviderDefinition) oidc.clone();
        assertEquals(oidc, oidc1);
    }

    @Test
    void oidcIdPPkceNotEqual() throws CloneNotSupportedException {
        OIDCIdentityProviderDefinition oidc1 = (OIDCIdentityProviderDefinition) oidc.clone();
        oidc.setPkce(false);
        assertNotEquals(oidc, oidc1);
    }

    @Test
    void oidcIdPPkceHashCodeNotEqual() throws CloneNotSupportedException {
        OIDCIdentityProviderDefinition oidc1 = (OIDCIdentityProviderDefinition) oidc.clone();
        oidc.setPkce(false);
        assertNotEquals(oidc.hashCode(), oidc1.hashCode());
    }

    @Test
    void oidcIdPPkceHashCodeEqual() throws CloneNotSupportedException {
        OIDCIdentityProviderDefinition oidc1 = (OIDCIdentityProviderDefinition) oidc.clone();
        assertEquals(oidc.hashCode(), oidc1.hashCode());
    }

    @Test
    void getIdpAuthenticationUrl_deactivatesPkce() {
        oauth.setRelyingPartySecret("secret");
        oauth.setPkce(false);
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authzUri = configurator.getIdpAuthenticationUrl(oauth, "alias", mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, not(hasKey("code_challenge")));
        assertThat(queryParams, not(hasKey("code_challenge_method")));
    }

    @Test
    void getIdpAuthenticationUrl_withOnlyDiscoveryUrlForOIDCProvider() throws MalformedURLException, OidcMetadataFetchingException {
        String discoveryUrl = "https://accounts.google.com/.well-known/openid-configuration";
        oidc.setDiscoveryUrl(new URL(discoveryUrl));
        oidc.setAuthUrl(null);
        doAnswer(invocation -> {
            OIDCIdentityProviderDefinition definition = invocation.getArgument(0);
            definition.setAuthUrl(new URL("https://accounts.google.com/o/oauth2/v2/auth"));
            return null;
        }).when(mockOidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authorizationURI = configurator.getIdpAuthenticationUrl(oidc, "alias", mockHttpServletRequest);

        assertThat(authorizationURI, Matchers.startsWith("https://accounts.google.com/o/oauth2/v2/auth"));
        verify(configurator).overlay(oidc);
    }

    @Test
    void getIdpAuthenticationUrl_hasAllRequiredQueryParametersForOidc() {
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");

        String authzUri = configurator.getIdpAuthenticationUrl(oidc, "alias", mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();

        assertThat(authzUri, startsWith(oidc.getAuthUrl().toString()));
        assertThat(queryParams, hasEntry("client_id", oidc.getRelyingPartyId()));
        assertThat(queryParams, hasEntry("response_type", "id_token+code"));
        assertThat(queryParams, hasEntry(is("redirect_uri"), containsString("login%2Fcallback%2Falias")));
        assertThat(queryParams, hasEntry("scope", "openid+password.write"));
        assertThat(queryParams, hasEntry("state", "01234567890123456789012345678901234567890123456789"));
        assertThat(queryParams, hasKey("nonce"));
    }

    @Test
    void getIdpAuthenticationUrl_hasAllRequiredQueryParametersForOauth() {
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");

        String authzUri = configurator.getIdpAuthenticationUrl(
                oauth,
                "alias",
                mockHttpServletRequest
        );

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();

        assertThat(authzUri, startsWith(oidc.getAuthUrl().toString()));
        assertThat(queryParams, hasEntry("client_id", oidc.getRelyingPartyId()));
        assertThat(queryParams, hasEntry("response_type", "code"));
        assertThat(queryParams, hasEntry(is("redirect_uri"), containsString("login%2Fcallback%2Falias")));
        assertThat(queryParams, hasEntry("scope", "openid+password.write"));
        assertThat(queryParams, hasEntry("state", "01234567890123456789012345678901234567890123456789"));
    }

    @Test
    void excludeUnreachableOidcProvider() throws OidcMetadataFetchingException {
        when(mockIdentityProviderProvisioning.retrieveAll(eq(true), anyString())).thenReturn(Arrays.asList(oidcProvider, oauthProvider, new IdentityProvider<>().setType(LDAP)));

        doThrow(new NullPointerException("")).when(mockOidcMetadataFetcher)
                .fetchMetadataAndUpdateDefinition(any(OIDCIdentityProviderDefinition.class));

        List<IdentityProvider> providers = configurator.retrieveAll(true, IdentityZone.getUaaZoneId());
        assertEquals(1, providers.size());
        assertEquals(oauthProvider.getName(), providers.get(0).getName());
        verify(configurator, times(1)).overlay(eq(config));
    }

    @Test
    void testGetIdpAuthenticationUrlAndCheckTokenFormatParameter() {
        when(mockUaaRandomStringUtil.getSecureRandom(anyInt())).thenReturn("01234567890123456789012345678901234567890123456789");
        String authzUri = configurator.getIdpAuthenticationUrl(oidc, OIDC10, mockHttpServletRequest);

        Map<String, String> queryParams =
                UriComponentsBuilder.fromUriString(authzUri).build().getQueryParams().toSingleValueMap();
        assertThat(queryParams, hasEntry("token_format", "jwt"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testIdpWithAliasExistsInZone(final boolean resultFromDelegate) {
        final String zoneId = RANDOM_STRING_GENERATOR.generate();
        when(mockIdentityProviderProvisioning.idpWithAliasExistsInZone(zoneId)).thenReturn(resultFromDelegate);
        assertEquals(resultFromDelegate, configurator.idpWithAliasExistsInZone(zoneId));
    }
}
