package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * UaaDelegatingLogoutSuccessHandler is a {@link LogoutSuccessHandler} that delegates to the appropriate
 * logout handler based on the authentication.
 * <p>
 * <li>If we have a valid SAML2 {@link Saml2AuthenticatedPrincipal} in the authentication, and have a
 * SingleLogoutServiceLocation set, then we will delegate to the {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler}.
 * <li> If we have a valid OAuth2 {@link AbstractExternalOAuthIdentityProviderDefinition} in the authentication,
 * then we will delegate to the {@link ExternalOAuthLogoutSuccessHandler}.
 * <li> Otherwise, we will delegate to the {@link ZoneAwareWhitelistLogoutSuccessHandler}.
 * <p>
 * On the LogoutResponse side, there is no Authentication available at that point, so will
 * always delegate to the {@link ZoneAwareWhitelistLogoutSuccessHandler}.
 * <p>
 * The LogoutResponse arrives on a new request to {@code /saml/SingleLogout/alias/{registrationId}} which
 * only carries {@code SAMLResponse} and {@code RelayState}. The parameters of the original
 * {@code /logout.do} request that determine the redirect target (e.g. {@code redirect} and
 * {@code client_id}) are therefore saved in the session before the LogoutRequest is sent, and restored
 * when the LogoutResponse is processed. This is the SAML counterpart of the OIDC flow, where
 * {@link ExternalOAuthLogoutSuccessHandler} passes the original logout URL as {@code post_logout_redirect_uri}.
 */
@Component
public class UaaDelegatingLogoutSuccessHandler implements LogoutSuccessHandler {
    static final String LOGOUT_PARAMETERS_SESSION_ATTRIBUTE =
            UaaDelegatingLogoutSuccessHandler.class.getName() + ".LOGOUT_PARAMETERS";

    // parameters evaluated by WhitelistLogoutSuccessHandler, besides the zone configurable redirect parameter
    private static final List<String> LOGOUT_PARAMETER_NAMES =
            List.of("client_id", "post_logout_redirect_uri", "id_token_hint");

    private final ZoneAwareWhitelistLogoutSuccessHandler zoneAwareWhitelistLogoutHandler;
    private final Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler;
    private final ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler;
    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;
    private final IdentityZoneManager identityZoneManager;

    public UaaDelegatingLogoutSuccessHandler(ZoneAwareWhitelistLogoutSuccessHandler zoneAwareWhitelistLogoutHandler,
            Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler,
            ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler,
            RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
            IdentityZoneManager identityZoneManager) {
        this.zoneAwareWhitelistLogoutHandler = zoneAwareWhitelistLogoutHandler;
        this.saml2RelyingPartyInitiatedLogoutSuccessHandler = saml2RelyingPartyInitiatedLogoutSuccessHandler;
        this.externalOAuthLogoutHandler = externalOAuthLogoutHandler;
        this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (shouldPerformSamlRelyingPartyLogout(request, authentication)) {
            saveLogoutParameters(request);
            saml2RelyingPartyInitiatedLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
            return;
        }

        if (authentication == null) {
            request = restoreLogoutParameters(request);
        }

        if (shouldPerformOAuthRpInitiatedLogout(authentication)) {
            externalOAuthLogoutHandler.onLogoutSuccess(request, response, authentication);
            return;
        }

        zoneAwareWhitelistLogoutHandler.onLogoutSuccess(request, response, authentication);
    }

    private boolean shouldPerformOAuthRpInitiatedLogout(Authentication authentication) {

        AbstractExternalOAuthIdentityProviderDefinition<OIDCIdentityProviderDefinition> oauthConfig = externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication);
        String logoutUrl = externalOAuthLogoutHandler.getLogoutUrl(oauthConfig);
        boolean shouldPerformRpInitiatedLogout = externalOAuthLogoutHandler.getPerformRpInitiatedLogout(oauthConfig);
        return shouldPerformRpInitiatedLogout && logoutUrl != null;
    }

    /**
     * Determines if the logout should follow the SAML protocol to the Asserting Party.
     */
    private boolean shouldPerformSamlRelyingPartyLogout(HttpServletRequest request, Authentication authentication) {
        if (authentication == null) {
            return false;
        }

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof Saml2AuthenticatedPrincipal samlPrincipal)) {
            return false;
        }

        String registrationId = samlPrincipal.getRelyingPartyRegistrationId();
        if (registrationId == null) {
            return false;
        }

        RelyingPartyRegistration registration = relyingPartyRegistrationResolver.resolve(request, registrationId);
        if (registration == null) {
            return false;
        }

        String singleLogoutServiceLocation = Optional.ofNullable(registration.getAssertingPartyMetadata()).map(AssertingPartyMetadata::getSingleLogoutServiceLocation).orElse(null);
        return singleLogoutServiceLocation != null;
    }

    private void saveLogoutParameters(HttpServletRequest request) {
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String name : logoutParameterNames()) {
            String value = request.getParameter(name);
            if (StringUtils.hasText(value)) {
                parameters.put(name, value);
            }
        }
        if (!parameters.isEmpty()) {
            request.getSession(true).setAttribute(LOGOUT_PARAMETERS_SESSION_ATTRIBUTE, parameters);
        }
    }

    private static HttpServletRequest restoreLogoutParameters(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return request;
        }
        Object saved = session.getAttribute(LOGOUT_PARAMETERS_SESSION_ATTRIBUTE);
        if (saved == null) {
            return request;
        }
        session.removeAttribute(LOGOUT_PARAMETERS_SESSION_ATTRIBUTE);
        if (!(saved instanceof Map<?, ?> savedParameters)) {
            return request;
        }

        Map<String, String[]> parameters = new HashMap<>();
        savedParameters.forEach((name, value) -> {
            if (name instanceof String parameterName && value instanceof String parameterValue) {
                parameters.put(parameterName, new String[]{parameterValue});
            }
        });
        // parameters of the incoming request always take precedence over the saved ones
        parameters.putAll(request.getParameterMap());
        return new LogoutParametersRequestWrapper(request, parameters);
    }

    private Set<String> logoutParameterNames() {
        Set<String> names = new LinkedHashSet<>();
        Optional.ofNullable(identityZoneManager.getCurrentIdentityZone())
                .map(IdentityZone::getConfig)
                .map(IdentityZoneConfiguration::getLinks)
                .map(links -> links.getLogout().getRedirectParameterName())
                .ifPresent(names::add);
        names.addAll(LOGOUT_PARAMETER_NAMES);
        return names;
    }

    private static class LogoutParametersRequestWrapper extends HttpServletRequestWrapper {
        private final Map<String, String[]> parameters;

        LogoutParametersRequestWrapper(HttpServletRequest request, Map<String, String[]> parameters) {
            super(request);
            this.parameters = Collections.unmodifiableMap(parameters);
        }

        @Override
        public String getParameter(String name) {
            String[] values = parameters.get(name);
            return values != null && values.length > 0 ? values[0] : null;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return parameters;
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(parameters.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            return parameters.get(name);
        }
    }
}
