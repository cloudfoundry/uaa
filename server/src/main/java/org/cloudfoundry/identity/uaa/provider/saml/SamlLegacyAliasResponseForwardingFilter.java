package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Redirects a request from /saml/SSO/alias/{registrationId}
 * to /login/saml2/sso/{relayState} which is the original registrationId,
 * that was passed with the SAMLRequest.
 */
@Component("samlLegacyAliasResponseForwardingFilter")
public class SamlLegacyAliasResponseForwardingFilter extends HttpFilter {

    public static final String DEFAULT_FILTER_PROCESSES_URI = "/saml/SSO/alias/{registrationId}";

    public static final String DEFAULT_FILTER_FORWARD_URI_PREFIX = "/login/saml2/sso/%s";

    private final RequestMatcher matcher;

    public SamlLegacyAliasResponseForwardingFilter() {
        matcher = new AntPathRequestMatcher(DEFAULT_FILTER_PROCESSES_URI);
    }

    @Override
    public void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        boolean match = this.matcher.matches(request);
        if (!match) {
            filterChain.doFilter(request, response);
            return;
        }
        String registrationId = request.getParameter(Saml2ParameterNames.RELAY_STATE);

        String forwardUrl = DEFAULT_FILTER_FORWARD_URI_PREFIX.formatted(registrationId);
        RequestDispatcher dispatcher = request.getRequestDispatcher(forwardUrl);
        dispatcher.forward(request, response);
    }
}
