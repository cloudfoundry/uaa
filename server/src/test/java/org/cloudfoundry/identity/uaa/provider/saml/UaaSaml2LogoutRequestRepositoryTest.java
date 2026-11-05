package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UaaSaml2LogoutRequestRepositoryTest {

    private static final String RELAY_STATE = "relay-state";
    private static final String REDIRECT = "https://app.example.com";

    @Mock
    private IdentityZoneManager identityZoneManager;

    private UaaSaml2LogoutRequestRepository repository;
    private MockHttpSession session;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        IdentityZone zone = new IdentityZone();
        zone.setConfig(new IdentityZoneConfiguration());
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(zone);

        repository = new UaaSaml2LogoutRequestRepository(identityZoneManager);
        session = new MockHttpSession();
        response = new MockHttpServletResponse();
    }

    @Test
    void savesOnlyParametersUsedToDetermineTheLogoutRedirect() {
        MockHttpServletRequest request = requestWithSession();
        request.setParameter("redirect", REDIRECT);
        request.setParameter("client_id", "client");
        request.setParameter("unrelated", "value");

        repository.saveLogoutRequest(logoutRequest(RELAY_STATE), request, response);

        assertThat(savedParameters())
                .extracting(
                        UaaSaml2LogoutRequestRepository.LogoutParameters::relayState,
                        UaaSaml2LogoutRequestRepository.LogoutParameters::parameters
                )
                .containsExactly(RELAY_STATE, Map.of("redirect", REDIRECT, "client_id", "client"));
    }

    @Test
    void usesTheRedirectParameterNameConfiguredForTheZone() {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getLinks().getLogout().setRedirectParameterName("goto");
        IdentityZone zone = new IdentityZone();
        zone.setConfig(config);
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(zone);
        MockHttpServletRequest request = requestWithSession();
        request.setParameter("goto", REDIRECT);
        request.setParameter("redirect", "https://ignored.example.com");

        repository.saveLogoutRequest(logoutRequest(RELAY_STATE), request, response);

        assertThat(savedParameters().parameterNames())
                .containsExactlyInAnyOrder("goto", "client_id", "post_logout_redirect_uri", "id_token_hint");
        assertThat(savedParameters().parameters()).containsExactlyEntriesOf(Map.of("goto", REDIRECT));
    }

    @Test
    void transfersParametersToTheCorrelatedResponseRequestAndRemovesThemFromTheSession() {
        MockHttpServletRequest logoutRequest = requestWithSession();
        logoutRequest.setParameter("redirect", REDIRECT);
        repository.saveLogoutRequest(logoutRequest(RELAY_STATE), logoutRequest, response);
        MockHttpServletRequest logoutResponse = requestWithSession();
        logoutResponse.setParameter("RelayState", RELAY_STATE);

        assertThat(repository.removeLogoutRequest(logoutResponse, response)).isNotNull();

        assertThat(session.getAttribute(UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_SESSION_ATTRIBUTE)).isNull();
        assertThat(logoutResponse.getAttribute(UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE))
                .isEqualTo(savedLogoutParameters(RELAY_STATE, Map.of("redirect", REDIRECT)));
    }

    @Test
    void doesNotConsumeParametersWhenRelayStateDoesNotMatch() {
        MockHttpServletRequest logoutRequest = requestWithSession();
        logoutRequest.setParameter("redirect", REDIRECT);
        repository.saveLogoutRequest(logoutRequest(RELAY_STATE), logoutRequest, response);
        MockHttpServletRequest logoutResponse = requestWithSession();
        logoutResponse.setParameter("RelayState", "other-state");

        assertThat(repository.removeLogoutRequest(logoutResponse, response)).isNull();

        assertThat(savedParameters()).isEqualTo(savedLogoutParameters(RELAY_STATE, Map.of("redirect", REDIRECT)));
        assertThat(logoutResponse.getAttribute(UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE))
                .isNull();
    }

    @Test
    void secondLogoutRequestReplacesParametersTogetherWithRelayState() {
        MockHttpServletRequest firstRequest = requestWithSession();
        firstRequest.setParameter("redirect", "https://first.example.com");
        repository.saveLogoutRequest(logoutRequest("first-state"), firstRequest, response);
        MockHttpServletRequest secondRequest = requestWithSession();
        secondRequest.setParameter("redirect", REDIRECT);
        repository.saveLogoutRequest(logoutRequest(RELAY_STATE), secondRequest, response);

        MockHttpServletRequest firstResponse = requestWithSession();
        firstResponse.setParameter("RelayState", "first-state");
        assertThat(repository.removeLogoutRequest(firstResponse, response)).isNull();
        assertThat(firstResponse.getAttribute(UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE))
                .isNull();

        MockHttpServletRequest secondResponse = requestWithSession();
        secondResponse.setParameter("RelayState", RELAY_STATE);
        assertThat(repository.removeLogoutRequest(secondResponse, response)).isNotNull();
        assertThat(secondResponse.getAttribute(UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE))
                .isEqualTo(savedLogoutParameters(RELAY_STATE, Map.of("redirect", REDIRECT)));
    }

    private MockHttpServletRequest requestWithSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return request;
    }

    private UaaSaml2LogoutRequestRepository.LogoutParameters savedParameters() {
        return (UaaSaml2LogoutRequestRepository.LogoutParameters) session.getAttribute(
                UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_SESSION_ATTRIBUTE
        );
    }

    private static UaaSaml2LogoutRequestRepository.LogoutParameters savedLogoutParameters(
            String relayState,
            Map<String, String> parameters
    ) {
        return new UaaSaml2LogoutRequestRepository.LogoutParameters(
                relayState,
                Set.of("redirect", "client_id", "post_logout_redirect_uri", "id_token_hint"),
                parameters
        );
    }

    private static Saml2LogoutRequest logoutRequest(String relayState) {
        RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
        return Saml2LogoutRequest.withRelyingPartyRegistration(registration)
                .samlRequest("request")
                .id("id")
                .relayState(relayState)
                .build();
    }
}
