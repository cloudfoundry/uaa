package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
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
import java.util.Set;

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
    private HttpServletRequest request;

    @Mock
    private Authentication authentication;

    private static final HttpServletResponse response = null;

    @BeforeEach
    void setup() {
        logoutSuccessHandler = new UaaDelegatingLogoutSuccessHandler(
                zoneAwareWhitelistLogoutHandler,
                saml2RelyingPartyInitiatedLogoutSuccessHandler,
                externalOAuthLogoutHandler,
                relyingPartyRegistrationResolver
        );
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
        private static final Set<String> LOGOUT_PARAMETER_NAMES =
                Set.of("redirect", "client_id", "post_logout_redirect_uri", "id_token_hint");

        @BeforeEach
        void setup() {
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
            HttpServletRequest forwarded =
                    logoutResponse(Map.of(), Map.of("redirect", URL, "client_id", CLIENT_ID));

            assertThat(forwarded.getParameter("redirect")).isEqualTo(URL);
            assertThat(forwarded.getParameter("client_id")).isEqualTo(CLIENT_ID);
            assertThat(forwarded.getParameter("SAMLResponse")).isEqualTo("response");
        }

        @Test
        void originalLogoutParametersTakePrecedenceOverCallbackParameters() throws Exception {
            HttpServletRequest forwarded = logoutResponse(
                    Map.of("redirect", "https://other.example.com", "client_id", "other-client"),
                    Map.of("redirect", URL, "client_id", CLIENT_ID)
            );

            assertThat(forwarded.getParameter("redirect")).isEqualTo(URL);
            assertThat(forwarded.getParameter("client_id")).isEqualTo(CLIENT_ID);
        }

        @Test
        void callbackCannotAddLogoutParametersMissingFromOriginalRequest() throws Exception {
            HttpServletRequest forwarded = logoutResponse(
                    Map.of("client_id", "other-client", "id_token_hint", "other-token"),
                    Map.of("redirect", URL)
            );

            assertThat(forwarded.getParameter("redirect")).isEqualTo(URL);
            assertThat(forwarded.getParameter("client_id")).isNull();
            assertThat(forwarded.getParameter("id_token_hint")).isNull();
        }

        @Test
        void doesNotRestoreParametersWithoutCorrelatedRequestAttribute() throws Exception {
            HttpServletRequest forwarded = logoutResponse(
                    Map.of("redirect", "https://callback.example.com"),
                    null
            );

            assertThat(forwarded.getParameter("redirect")).isEqualTo("https://callback.example.com");
        }

        private HttpServletRequest logoutResponse(
                Map<String, String> callbackParameters,
                Map<String, String> savedParameters
        ) throws Exception {
            MockHttpServletRequest logoutResponse = new MockHttpServletRequest("GET", "/saml/SingleLogout/alias/" + REG_ID);
            logoutResponse.setParameter("SAMLResponse", "response");
            logoutResponse.setParameter("RelayState", "relay-state");
            logoutResponse.addParameters(callbackParameters);
            if (savedParameters != null) {
                logoutResponse.setAttribute(
                        UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE,
                        new UaaSaml2LogoutRequestRepository.LogoutParameters(
                                "relay-state",
                                LOGOUT_PARAMETER_NAMES,
                                savedParameters
                        )
                );
            }
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
