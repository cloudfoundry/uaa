package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UaaDelegatingLogoutSuccessHandlerTest {

    private static final String REG_ID = "regId";
    private static final String URL = "https://url.com";
    UaaDelegatingLogoutSuccessHandler logoutSuccessHandler;

    @Mock
    private ZoneAwareWhitelistLogoutSuccessHandler zoneAwareWhitelistLogoutHandler;

    @Mock
    private Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler;

    @Mock
    private ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler;

    @Mock
    private RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

    @Mock
    private HttpServletRequest request;

    @Mock
    private Authentication authentication;

    private static final HttpServletResponse response = null;

    @BeforeEach
    void setup() {
        logoutSuccessHandler = new UaaDelegatingLogoutSuccessHandler(zoneAwareWhitelistLogoutHandler, saml2RelyingPartyInitiatedLogoutSuccessHandler, externalOAuthLogoutHandler, relyingPartyRegistrationResolver);
    }

    @Test
    void fallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void shouldPerformOAuthRpInitiatedLogout() throws ServletException, IOException {
        var oauthConfig = mock(AbstractExternalOAuthIdentityProviderDefinition.class);
        when(externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication)).thenReturn(oauthConfig);
        when(externalOAuthLogoutHandler.getLogoutUrl(oauthConfig)).thenReturn(URL);
        when(externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig)).thenReturn(true);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, true, false);
    }

    @Test
    void shouldPerformSamlRelyingPartyLogout() throws ServletException, IOException {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
        var mockRegistration = mock(RelyingPartyRegistration.class);
        when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);
        var mockAssertingPartyDetails = mock(RelyingPartyRegistration.AssertingPartyDetails.class);
        when(mockRegistration.getAssertingPartyDetails()).thenReturn(mockAssertingPartyDetails);
        when(mockAssertingPartyDetails.getSingleLogoutServiceLocation()).thenReturn(URL);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(true, false, false);
    }

    /*
     * Negative Tests for saml2RelyingPartyInitiatedLogoutSuccessHandler
     */

    @Test
    void nullAuthFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        logoutSuccessHandler.onLogoutSuccess(request, response, null);
        verify(zoneAwareWhitelistLogoutHandler).onLogoutSuccess(request, response, null);
        verify(externalOAuthLogoutHandler, never()).onLogoutSuccess(any(), any(), any());
        verify(saml2RelyingPartyInitiatedLogoutSuccessHandler, never()).onLogoutSuccess(any(), any(), any());
    }

    @Test
    void nullRegIdFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void nullRegistrationFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void nullAssertingPartyDetailsFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
        var mockRegistration = mock(RelyingPartyRegistration.class);
        when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void nullSingleLogoutServiceLocationFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
        var mockRegistration = mock(RelyingPartyRegistration.class);
        when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);
        var mockAssertingPartyDetails = mock(RelyingPartyRegistration.AssertingPartyDetails.class);
        when(mockRegistration.getAssertingPartyDetails()).thenReturn(mockAssertingPartyDetails);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    /*
     * Negative Tests for externalOAuthLogoutHandler
     */

    @Test
    void nullLogoutUrlFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        var oauthConfig = mock(AbstractExternalOAuthIdentityProviderDefinition.class);
        when(externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication)).thenReturn(oauthConfig);
        when(externalOAuthLogoutHandler.getLogoutUrl(oauthConfig)).thenReturn(null);
        when(externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig)).thenReturn(true);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void falsePerformRpInitiatedLogoutFallsThruToZoneAwareWhitelistLogoutHandler() throws ServletException, IOException {
        var oauthConfig = mock(AbstractExternalOAuthIdentityProviderDefinition.class);
        when(externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication)).thenReturn(oauthConfig);
        when(externalOAuthLogoutHandler.getLogoutUrl(oauthConfig)).thenReturn(URL);
        when(externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig)).thenReturn(false);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    private void verifyCorrectOnLogoutSuccessCalled(boolean saml, boolean oAuth, boolean zoneAware) throws IOException, ServletException {
        if (saml) {
            verify(saml2RelyingPartyInitiatedLogoutSuccessHandler).onLogoutSuccess(request, response, authentication);
        } else {
            verify(saml2RelyingPartyInitiatedLogoutSuccessHandler, never()).onLogoutSuccess(any(), any(), any());
        }

        if (oAuth) {
            verify(externalOAuthLogoutHandler).onLogoutSuccess(request, response, authentication);
        } else {
            verify(externalOAuthLogoutHandler, never()).onLogoutSuccess(any(), any(), any());
        }

        if (zoneAware) {
            verify(zoneAwareWhitelistLogoutHandler).onLogoutSuccess(request, response, authentication);
        } else {
            verify(zoneAwareWhitelistLogoutHandler, never()).onLogoutSuccess(any(), any(), any());
        }
    }
}
