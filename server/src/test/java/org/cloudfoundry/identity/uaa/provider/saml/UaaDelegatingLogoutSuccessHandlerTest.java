package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
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
    private IdentityZoneManager identityZoneManager;

    @Mock
    private HttpServletRequest request;

    @Mock
    private Authentication authentication;

    private static final HttpServletResponse response = null;

    @BeforeEach
    void setup() {
        IdentityZone zone = new IdentityZone();
        zone.setConfig(new IdentityZoneConfiguration());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(zone);
        logoutSuccessHandler = new UaaDelegatingLogoutSuccessHandler(zoneAwareWhitelistLogoutHandler, saml2RelyingPartyInitiatedLogoutSuccessHandler, externalOAuthLogoutHandler, relyingPartyRegistrationResolver, identityZoneManager);
    }

    @Test
    void fallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void shouldPerformOAuthRpInitiatedLogout() throws Exception {
        var oauthConfig = mock(AbstractExternalOAuthIdentityProviderDefinition.class);
        when(externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication)).thenReturn(oauthConfig);
        when(externalOAuthLogoutHandler.getLogoutUrl(oauthConfig)).thenReturn(URL);
        when(externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig)).thenReturn(true);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, true, false);
    }

    @Test
    void shouldPerformSamlRelyingPartyLogout() throws Exception {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
        var mockRegistration = mock(RelyingPartyRegistration.class);
        when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);
        var mockAssertingPartyDetails = mock(AssertingPartyMetadata.class);
        when(mockRegistration.getAssertingPartyMetadata()).thenReturn(mockAssertingPartyDetails);
        when(mockAssertingPartyDetails.getSingleLogoutServiceLocation()).thenReturn(URL);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(true, false, false);
    }

    /*
     * Negative Tests for saml2RelyingPartyInitiatedLogoutSuccessHandler
     */

    @Test
    void nullAuthFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        logoutSuccessHandler.onLogoutSuccess(request, response, null);
        verify(zoneAwareWhitelistLogoutHandler).onLogoutSuccess(request, response, null);
        verify(externalOAuthLogoutHandler, never()).onLogoutSuccess(any(), any(), any());
        verify(saml2RelyingPartyInitiatedLogoutSuccessHandler, never()).onLogoutSuccess(any(), any(), any());
    }

    @Test
    void nullRegIdFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void nullRegistrationFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void nullAssertingPartyDetailsFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
        var mockRegistration = mock(RelyingPartyRegistration.class);
        when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void nullSingleLogoutServiceLocationFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        var mockPrincipal = mock(UaaSamlPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(mockPrincipal);
        when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
        var mockRegistration = mock(RelyingPartyRegistration.class);
        when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);
        var mockAssertingPartyDetails = mock(AssertingPartyMetadata.class);
        when(mockRegistration.getAssertingPartyMetadata()).thenReturn(mockAssertingPartyDetails);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    /*
     * Negative Tests for externalOAuthLogoutHandler
     */

    @Test
    void nullLogoutUrlFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        var oauthConfig = mock(AbstractExternalOAuthIdentityProviderDefinition.class);
        when(externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication)).thenReturn(oauthConfig);
        when(externalOAuthLogoutHandler.getLogoutUrl(oauthConfig)).thenReturn(null);
        when(externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig)).thenReturn(true);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    @Test
    void falsePerformRpInitiatedLogoutFallsThruToZoneAwareWhitelistLogoutHandler() throws Exception {
        var oauthConfig = mock(AbstractExternalOAuthIdentityProviderDefinition.class);
        when(externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication)).thenReturn(oauthConfig);
        when(externalOAuthLogoutHandler.getLogoutUrl(oauthConfig)).thenReturn(URL);
        when(externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig)).thenReturn(false);

        logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
        verifyCorrectOnLogoutSuccessCalled(false, false, true);
    }

    /*
     * The LogoutResponse of the Asserting Party arrives on a separate request, without the parameters of /logout.do
     */
    @Nested
    class LogoutParametersAcrossSamlSingleLogout {
        private static final String CLIENT_ID = "a-client-id";

        private MockHttpSession session;

        @BeforeEach
        void setup() {
            session = new MockHttpSession();
            var mockPrincipal = mock(UaaSamlPrincipal.class);
            when(authentication.getPrincipal()).thenReturn(mockPrincipal);
            when(mockPrincipal.getRelyingPartyRegistrationId()).thenReturn(REG_ID);
            var mockRegistration = mock(RelyingPartyRegistration.class);
            when(relyingPartyRegistrationResolver.resolve(any(), eq(REG_ID))).thenReturn(mockRegistration);
            var mockAssertingPartyDetails = mock(AssertingPartyMetadata.class);
            when(mockRegistration.getAssertingPartyMetadata()).thenReturn(mockAssertingPartyDetails);
            when(mockAssertingPartyDetails.getSingleLogoutServiceLocation()).thenReturn(URL);
        }

        @Test
        void restoresRedirectAndClientIdWhenTheLogoutResponseIsProcessed() throws Exception {
            logoutDo(Map.of("redirect", URL, "client_id", CLIENT_ID));

            HttpServletRequest forwarded = logoutResponse(Map.of());

            assertThat(forwarded.getParameter("redirect")).isEqualTo(URL);
            assertThat(forwarded.getParameter("client_id")).isEqualTo(CLIENT_ID);
            assertThat(forwarded.getParameter("SAMLResponse")).isEqualTo("response");
            assertThat(session.getAttribute(UaaDelegatingLogoutSuccessHandler.LOGOUT_PARAMETERS_SESSION_ATTRIBUTE)).isNull();
        }

        @Test
        void savesOnlyTheParametersRelevantForTheRedirect() throws Exception {
            logoutDo(Map.of("redirect", URL, "client_id", CLIENT_ID, "post_logout_redirect_uri", URL,
                    "id_token_hint", "token", "unrelated", "value"));

            assertThat(session.getAttribute(UaaDelegatingLogoutSuccessHandler.LOGOUT_PARAMETERS_SESSION_ATTRIBUTE))
                    .isEqualTo(Map.of("redirect", URL, "client_id", CLIENT_ID, "post_logout_redirect_uri", URL,
                            "id_token_hint", "token"));
        }

        @Test
        void usesTheRedirectParameterNameConfiguredForTheZone() throws Exception {
            IdentityZoneConfiguration config = new IdentityZoneConfiguration();
            config.getLinks().getLogout().setRedirectParameterName("goto");
            IdentityZone zone = new IdentityZone();
            zone.setConfig(config);
            when(identityZoneManager.getCurrentIdentityZone()).thenReturn(zone);

            logoutDo(Map.of("goto", URL, "redirect", "https://ignored.example.com"));

            HttpServletRequest forwarded = logoutResponse(Map.of());
            assertThat(forwarded.getParameter("goto")).isEqualTo(URL);
            assertThat(forwarded.getParameter("redirect")).isNull();
        }

        @Test
        void parametersOfTheLogoutResponseRequestTakePrecedence() throws Exception {
            logoutDo(Map.of("redirect", URL, "client_id", CLIENT_ID));

            HttpServletRequest forwarded = logoutResponse(Map.of("redirect", "https://other.example.com"));

            assertThat(forwarded.getParameter("redirect")).isEqualTo("https://other.example.com");
            assertThat(forwarded.getParameter("client_id")).isEqualTo(CLIENT_ID);
        }

        @Test
        void doesNotCreateASessionWhenThereIsNothingToSave() throws Exception {
            MockHttpServletRequest logoutDo = new MockHttpServletRequest("GET", "/logout.do");

            logoutSuccessHandler.onLogoutSuccess(logoutDo, response, authentication);

            assertThat(logoutDo.getSession(false)).isNull();
        }

        @Test
        void savedParametersAreUsedOnlyOnce() throws Exception {
            logoutDo(Map.of("redirect", URL, "client_id", CLIENT_ID));
            logoutResponse(Map.of());

            HttpServletRequest forwarded = logoutResponse(Map.of());

            assertThat(forwarded.getParameter("redirect")).isNull();
        }

        private void logoutDo(Map<String, String> parameters) throws Exception {
            MockHttpServletRequest logoutDo = new MockHttpServletRequest("GET", "/logout.do");
            logoutDo.setSession(session);
            logoutDo.setParameters(parameters);
            logoutSuccessHandler.onLogoutSuccess(logoutDo, response, authentication);
            verify(saml2RelyingPartyInitiatedLogoutSuccessHandler).onLogoutSuccess(logoutDo, response, authentication);
        }

        private HttpServletRequest logoutResponse(Map<String, String> parameters) throws Exception {
            MockHttpServletRequest logoutResponse = new MockHttpServletRequest("GET", "/saml/SingleLogout/alias/" + REG_ID);
            logoutResponse.setSession(session);
            logoutResponse.setParameter("SAMLResponse", "response");
            logoutResponse.setParameter("RelayState", "relay-state");
            logoutResponse.addParameters(parameters);
            clearInvocations(zoneAwareWhitelistLogoutHandler);

            logoutSuccessHandler.onLogoutSuccess(logoutResponse, response, null);

            ArgumentCaptor<HttpServletRequest> forwarded = ArgumentCaptor.forClass(HttpServletRequest.class);
            verify(zoneAwareWhitelistLogoutHandler).onLogoutSuccess(forwarded.capture(), eq(response), eq(null));
            return forwarded.getValue();
        }
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
