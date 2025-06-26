package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExternalOAuthLogoutSuccessHandlerTest {
    private static final String UAA_ENDSESSION_URL = "http://localhost:8080/uaa/logout.do";

    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private OIDCIdentityProviderDefinition oAuthIdentityProviderDefinition;

    private ExternalOAuthLogoutSuccessHandler oAuthLogoutHandler = mock(ExternalOAuthLogoutSuccessHandler.class);
    IdentityZoneConfiguration configuration = new IdentityZoneConfiguration();
    IdentityZoneConfiguration original;

    @Mock(lenient = true)
    private IdentityProviderProvisioning providerProvisioning;

    @Mock
    private OidcMetadataFetcher oidcMetadataFetcher;

    @Mock(lenient = true)
    private UaaAuthentication uaaAuthentication;

    @Mock(lenient = true)
    private UaaPrincipal uaaPrincipal;

    @Mock(lenient = true)
    private IdentityZoneManager identityZoneManager;

    @BeforeEach
    void setUp() throws MalformedURLException {
        IdentityZone uaaZone = IdentityZone.getUaa();
        original = IdentityZone.getUaa().getConfig();
        configuration.getLinks().getLogout()
                .setRedirectUrl("/login")
                .setDisableRedirectParameter(true)
                .setRedirectParameterName("redirect");
        uaaZone.setConfig(configuration);
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.OIDC10);
        identityProvider.setOriginKey("test");
        identityProvider.setId("id");
        identityProvider.setName("name");
        identityProvider.setActive(true);
        oAuthIdentityProviderDefinition = new OIDCIdentityProviderDefinition();
        oAuthIdentityProviderDefinition.setLogoutUrl(URI.create(UAA_ENDSESSION_URL).toURL());
        oAuthIdentityProviderDefinition.setRelyingPartyId("id");
        identityProvider.setConfig(oAuthIdentityProviderDefinition);
        when(providerProvisioning.retrieveByOrigin("test", "uaa")).thenReturn(identityProvider);
        when(uaaAuthentication.getPrincipal()).thenReturn(uaaPrincipal);
        when(uaaAuthentication.getAuthenticationMethods()).thenReturn(Set.of("ext", "oauth"));
        when(uaaPrincipal.getOrigin()).thenReturn("test");
        when(uaaPrincipal.getZoneId()).thenReturn("uaa");
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(uaaZone);
        oAuthLogoutHandler = new ExternalOAuthLogoutSuccessHandler(providerProvisioning, oidcMetadataFetcher, identityZoneManager);
        IdentityZoneHolder.get().setConfig(configuration);
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        IdentityZone.getUaa().setConfig(original);
        SecurityContextHolder.clearContext();
        request.setQueryString(null);
    }

    @Test
    void determineTargetUrl() {
        request.setQueryString("parameter=value");
        assertThat(oAuthLogoutHandler.determineTargetUrl(request, response, uaaAuthentication)).isEqualTo("http://localhost:8080/uaa/logout.do?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3Fparameter%3Dvalue&client_id=id");
    }

    @Test
    void determineTargetUrlWithIdTokenHint() {
        request.setQueryString("parameter=value");
        when(uaaAuthentication.getIdpIdToken()).thenReturn("token");
        assertThat(oAuthLogoutHandler.determineTargetUrl(request, response, uaaAuthentication))
                .isEqualTo("http://localhost:8080/uaa/logout.do?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3Fparameter%3Dvalue&client_id=id&id_token_hint=token");
    }

    @Test
    void determineDefaultTargetUrl() {
        oAuthIdentityProviderDefinition.setLogoutUrl(null);
        IdentityZoneHolder.get().setConfig(null);
        assertThat(oAuthLogoutHandler.determineTargetUrl(request, response, uaaAuthentication)).isEqualTo("/login");
    }

    @Test
    void constructOAuthProviderLogoutUrl() {
        String url = oAuthLogoutHandler.constructOAuthProviderLogoutUrl(request, "", oAuthIdentityProviderDefinition, uaaAuthentication);
        assertThat(url).isEqualTo("?post_logout_redirect_uri=http%3A%2F%2Flocalhost&client_id=id");
    }

    @Test
    void getLogoutUrl() throws OidcMetadataFetchingException {
        assertThat(oAuthLogoutHandler.getLogoutUrl(oAuthIdentityProviderDefinition)).isEqualTo(UAA_ENDSESSION_URL);
        verify(oidcMetadataFetcher, times(0)).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
    }

    @Test
    void getNewFetchedLogoutUrl() throws OidcMetadataFetchingException {
        oAuthIdentityProviderDefinition.setLogoutUrl(null);
        assertThat(oAuthLogoutHandler.getLogoutUrl(oAuthIdentityProviderDefinition)).isNull();
        verify(oidcMetadataFetcher, times(1)).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
    }

    @Test
    void getNewInvalidFetchedLogoutUrl() throws OidcMetadataFetchingException {
        oAuthIdentityProviderDefinition.setLogoutUrl(null);
        doThrow(new OidcMetadataFetchingException("")).when(oidcMetadataFetcher).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
        assertThat(oAuthLogoutHandler.getLogoutUrl(oAuthIdentityProviderDefinition)).isNull();
        verify(oidcMetadataFetcher, times(1)).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
    }

    @Test
    void getOAuthProviderForAuthentication() {
        assertThat(oAuthLogoutHandler.getOAuthProviderForAuthentication(uaaAuthentication)).isEqualTo(oAuthIdentityProviderDefinition);
    }

    @Test
    void getNullOAuthProviderForAuthentication() {
        assertThat(oAuthLogoutHandler.getOAuthProviderForAuthentication(null)).isNull();
    }

    @Test
    void getPerformRpInitiatedLogout() {
        oAuthIdentityProviderDefinition.setPerformRpInitiatedLogout(true);
        assertThat(oAuthLogoutHandler.getPerformRpInitiatedLogout(oAuthIdentityProviderDefinition)).isTrue();

        oAuthIdentityProviderDefinition.setPerformRpInitiatedLogout(false);
        assertThat(oAuthLogoutHandler.getPerformRpInitiatedLogout(oAuthIdentityProviderDefinition)).isFalse();

        assertThat(oAuthLogoutHandler.getPerformRpInitiatedLogout(null)).isFalse();
    }
}