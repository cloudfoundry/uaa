package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.authentication.SamlLogoutResponseValidator;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml5LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.web.util.UriComponentsBuilder.fromUriString;

/**
 * Exercises a complete relying-party-initiated SAML Single Logout round-trip, with the asserting
 * party (an ADFS-style IdP that advertises a SingleLogoutService) simulated in-process.
 * <p>
 * The outgoing leg is produced by the real {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler}
 * and the return leg is consumed by the real {@link Saml2LogoutResponseFilter}, so the test covers
 * what the user agent actually does: two separate HTTP requests, correlated only by the session and
 * the {@code RelayState}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SamlLogoutRoundTripTest {

    private static final String REGISTRATION_ID = "openam";
    private static final String CLIENT_ID = "a-client-id";
    private static final String SP_URI = "https://app.example.com";

    @Mock
    private MultitenantClientServices clientDetailsService;
    @Mock
    private KeyInfoService keyInfoService;
    @Mock
    private ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler;

    private RelyingPartyRegistration registration;
    private UaaDelegatingLogoutSuccessHandler delegatingLogoutSuccessHandler;
    private Saml2LogoutResponseFilter logoutResponseFilter;
    private UaaSaml2LogoutRequestRepository logoutRequestRepository;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
        SamlConfiguration.setupOpenSaml();
    }

    @BeforeEach
    void setUp() {
        registration = TestRelyingPartyRegistrations.full()
                .registrationId(REGISTRATION_ID)
                .nameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                .singleLogoutServiceBindings(bindings -> {
                    bindings.clear();
                    bindings.add(Saml2MessageBinding.REDIRECT);
                })
                .assertingPartyMetadata(party -> party.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT))
                .build();

        RelyingPartyRegistrationResolver registrationResolver = (request, id) -> registration;

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.getLinks().getLogout().setRedirectUrl("/login").setRedirectParameterName("redirect");
        IdentityZoneHolder.get().setConfig(config);

        when(clientDetailsService.loadClientByClientId(eq(CLIENT_ID), any()))
                .thenReturn(new UaaClientDetails(CLIENT_ID, "", "", "", "", SP_URI));

        logoutRequestRepository = new UaaSaml2LogoutRequestRepository(new IdentityZoneManagerImpl());
        Saml2RelyingPartyInitiatedLogoutSuccessHandler samlLogoutSuccessHandler =
                new Saml2RelyingPartyInitiatedLogoutSuccessHandler(
                        new OpenSaml5LogoutRequestResolver(registrationResolver));
        samlLogoutSuccessHandler.setLogoutRequestRepository(logoutRequestRepository);
        delegatingLogoutSuccessHandler = new UaaDelegatingLogoutSuccessHandler(
                new ZoneAwareWhitelistLogoutSuccessHandler(clientDetailsService, externalOAuthLogoutHandler, keyInfoService),
                samlLogoutSuccessHandler,
                externalOAuthLogoutHandler,
                registrationResolver);

        // wired as in SamlAuthenticationFilterConfig#saml2LogoutResponseFilter
        logoutResponseFilter = new Saml2LogoutResponseFilter(registrationResolver,
                new SamlLogoutResponseValidator(),
                delegatingLogoutSuccessHandler);
        logoutResponseFilter.setLogoutRequestMatcher(AnyRequestMatcher.INSTANCE);
        logoutResponseFilter.setLogoutRequestRepository(logoutRequestRepository);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void returnsToTheServiceProviderAfterTheAssertingPartyRespondsToTheLogoutRequest() throws Exception {
        MockHttpSession session = new MockHttpSession();

        String relayState = whenTheUserLogsOut(session, SP_URI);
        MockHttpServletResponse response = whenTheAssertingPartyRespondsWithSuccess(session, relayState);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo(SP_URI);
    }

    @Test
    void fallsBackToTheZoneDefaultWhenTheLogoutRequestCarriedNoRedirect() throws Exception {
        MockHttpSession session = new MockHttpSession();

        String relayState = whenTheUserLogsOut(session, null);
        MockHttpServletResponse response = whenTheAssertingPartyRespondsWithSuccess(session, relayState);

        assertThat(response.getRedirectedUrl()).isEqualTo("/login");
    }

    @Test
    void doesNotRedirectToARedirectTargetThatIsNotRegisteredForTheClient() throws Exception {
        MockHttpSession session = new MockHttpSession();

        String relayState = whenTheUserLogsOut(session, "https://not-registered.example.com");
        MockHttpServletResponse response = whenTheAssertingPartyRespondsWithSuccess(session, relayState);

        assertThat(response.getRedirectedUrl()).isEqualTo("/login");
    }

    @Test
    void ignoresLogoutRedirectParametersAddedByTheAssertingPartyCallback() throws Exception {
        MockHttpSession session = new MockHttpSession();

        String relayState = whenTheUserLogsOut(session, SP_URI);
        MockHttpServletResponse response = whenTheAssertingPartyResponds(
                session,
                relayState,
                logoutResponse(),
                Map.of("redirect", "https://callback.example.com", "client_id", "other-client")
        );

        assertThat(response.getRedirectedUrl()).isEqualTo(SP_URI);
    }

    @Test
    void removesSavedLogoutParametersWhenTheLogoutResponseIsInvalid() throws Exception {
        MockHttpSession session = new MockHttpSession();

        String relayState = whenTheUserLogsOut(session, SP_URI);
        MockHttpServletResponse response = whenTheAssertingPartyResponds(
                session,
                relayState,
                logoutResponse("https://unexpected-idp.example.com"),
                Map.of()
        );

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(session.getAttribute(UaaSaml2LogoutRequestRepository.LOGOUT_PARAMETERS_SESSION_ATTRIBUTE)).isNull();
    }

    /**
     * GET /logout.do?client_id=...&redirect=... - returns the RelayState of the emitted LogoutRequest.
     */
    private String whenTheUserLogsOut(MockHttpSession session, String redirect) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/logout.do");
        request.setSession(session);
        request.setParameter("client_id", CLIENT_ID);
        if (redirect != null) {
            request.setParameter("redirect", redirect);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();

        delegatingLogoutSuccessHandler.onLogoutSuccess(request, response, samlAuthentication());

        String location = response.getRedirectedUrl();
        assertThat(location)
                .as("the user agent must be sent to the asserting party's SingleLogoutService")
                .startsWith(registration.getAssertingPartyMetadata().getSingleLogoutServiceLocation());

        var parameters = fromUriString(location).build().getQueryParams();
        assertThat(parameters.getFirst("SAMLRequest")).isNotNull();
        return parameters.getFirst("RelayState");
    }

    /**
     * The asserting party terminates its session and sends the user agent back to UAA with a
     * successful LogoutResponse, echoing the RelayState, on a request that carries nothing else.
     */
    private MockHttpServletResponse whenTheAssertingPartyRespondsWithSuccess(MockHttpSession session, String relayState)
            throws Exception {
        return whenTheAssertingPartyResponds(session, relayState, logoutResponse(), Map.of());
    }

    private MockHttpServletResponse whenTheAssertingPartyResponds(
            MockHttpSession session,
            String relayState,
            String samlResponse,
            Map<String, String> callbackParameters
    ) throws Exception {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", "/saml/SingleLogout/alias/" + REGISTRATION_ID);
        request.setSession(session);
        request.setParameter("SAMLResponse", samlResponse);
        request.setParameter("RelayState", relayState);
        request.addParameters(callbackParameters);
        MockHttpServletResponse response = new MockHttpServletResponse();

        logoutResponseFilter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private String logoutResponse() {
        return logoutResponse(registration.getAssertingPartyMetadata().getEntityId());
    }

    private String logoutResponse(String issuer) {
        String xml = """
                <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_%s" Version="2.0" Destination="%s">
                  <saml:Issuer>%s</saml:Issuer>
                  <samlp:Status>
                    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                  </samlp:Status>
                </samlp:LogoutResponse>
                """.formatted(UUID.randomUUID(),
                registration.getSingleLogoutServiceResponseLocation(),
                issuer);
        return Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
    }

    private static Authentication samlAuthentication() {
        UaaSamlPrincipal principal = new UaaSamlPrincipal("user-id", "marissa", "marissa@test.org",
                REGISTRATION_ID, List.of("a-session-index"), "marissa", "uaa");
        return new UsernamePasswordAuthenticationToken(principal, null, List.of());
    }
}
