package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.Serial;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class UaaSaml2LogoutRequestRepository implements Saml2LogoutRequestRepository {

    static final String LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE =
            UaaSaml2LogoutRequestRepository.class.getName() + ".LOGOUT_PARAMETERS";
    static final String LOGOUT_PARAMETERS_SESSION_ATTRIBUTE =
            UaaSaml2LogoutRequestRepository.class.getName() + ".LOGOUT_PARAMETERS";

    private static final List<String> LOGOUT_PARAMETER_NAMES =
            List.of("client_id", "post_logout_redirect_uri", "id_token_hint");

    private final IdentityZoneManager identityZoneManager;
    private final Saml2LogoutRequestRepository delegate;

    UaaSaml2LogoutRequestRepository(IdentityZoneManager identityZoneManager) {
        this(identityZoneManager, new HttpSessionLogoutRequestRepository());
    }

    UaaSaml2LogoutRequestRepository(
            IdentityZoneManager identityZoneManager,
            Saml2LogoutRequestRepository delegate
    ) {
        this.identityZoneManager = identityZoneManager;
        this.delegate = delegate;
    }

    @Override
    public Saml2LogoutRequest loadLogoutRequest(HttpServletRequest request) {
        return delegate.loadLogoutRequest(request);
    }

    @Override
    public void saveLogoutRequest(
            Saml2LogoutRequest logoutRequest,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        delegate.saveLogoutRequest(logoutRequest, request, response);

        HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        if (logoutRequest == null) {
            session.removeAttribute(LOGOUT_PARAMETERS_SESSION_ATTRIBUTE);
            return;
        }

        Set<String> parameterNames = logoutParameterNames();
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String name : parameterNames) {
            String value = request.getParameter(name);
            if (StringUtils.hasText(value)) {
                parameters.put(name, value);
            }
        }

        session.setAttribute(
                LOGOUT_PARAMETERS_SESSION_ATTRIBUTE,
                new LogoutParameters(logoutRequest.getRelayState(), parameterNames, parameters)
        );
    }

    @Override
    public Saml2LogoutRequest removeLogoutRequest(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        Saml2LogoutRequest logoutRequest = delegate.removeLogoutRequest(request, response);
        if (logoutRequest == null) {
            return null;
        }

        HttpSession session = request.getSession(false);
        if (session == null) {
            return logoutRequest;
        }
        Object saved = session.getAttribute(LOGOUT_PARAMETERS_SESSION_ATTRIBUTE);
        session.removeAttribute(LOGOUT_PARAMETERS_SESSION_ATTRIBUTE);
        if (saved instanceof LogoutParameters logoutParameters
                && logoutParameters.relayState().equals(logoutRequest.getRelayState())) {
            request.setAttribute(LOGOUT_PARAMETERS_REQUEST_ATTRIBUTE, logoutParameters);
        }
        return logoutRequest;
    }

    private Set<String> logoutParameterNames() {
        Set<String> names = new LinkedHashSet<>();
        String redirectParameterName = identityZoneManager.getCurrentIdentityZone()
                .getConfig()
                .getLinks()
                .getLogout()
                .getRedirectParameterName();
        if (StringUtils.hasText(redirectParameterName)) {
            names.add(redirectParameterName);
        }
        names.addAll(LOGOUT_PARAMETER_NAMES);
        return names;
    }

    record LogoutParameters(
            String relayState,
            Set<String> parameterNames,
            Map<String, String> parameters
    ) implements Serializable {

        @Serial
        private static final long serialVersionUID = 1L;

        LogoutParameters {
            parameterNames = Set.copyOf(parameterNames);
            parameters = Map.copyOf(parameters);
        }
    }
}
