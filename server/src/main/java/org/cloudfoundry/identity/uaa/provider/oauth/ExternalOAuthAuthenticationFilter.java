package org.cloudfoundry.identity.uaa.provider.oauth;

import org.apache.commons.io.FilenameUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.web.HttpSessionRequiredException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class ExternalOAuthAuthenticationFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(ExternalOAuthAuthenticationFilter.class);

    private final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private final AccountSavingAuthenticationSuccessHandler successHandler;

    public ExternalOAuthAuthenticationFilter(
            final ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager,
            final AccountSavingAuthenticationSuccessHandler successHandler) {
        this.externalOAuthAuthenticationManager = externalOAuthAuthenticationManager;
        this.successHandler = successHandler;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(
            final ServletRequest servletRequest,
            final ServletResponse servletResponse,
            final FilterChain chain
    ) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (!containsCredentials(request)) {
            request.getRequestDispatcher("/login_implicit").forward(request, response);
            return;
        }

        checkRequestStateParameter(request);

        if (authenticationWasSuccessful(request, response)) {
            chain.doFilter(request, response);
        }
    }

    private void checkRequestStateParameter(final HttpServletRequest request)
            throws HttpSessionRequiredException {
        final String originKey = UaaUrlUtils.extractPathVariableFromUrl(2, request.getServletPath());
        final HttpSession session = request.getSession();
        if (session == null) {
            throw new HttpSessionRequiredException("An HTTP Session is required to process request.");
        }
        final Object stateInSession = SessionUtils.getStateParam(session, SessionUtils.stateParameterAttributeKeyForIdp(originKey));
        final String stateFromParameters = request.getParameter("state");
        if (UaaStringUtils.isEmpty(stateFromParameters) || !stateFromParameters.equals(stateInSession)) {
            throw new CsrfException("Invalid State Param in request.");
        }
    }

    private boolean containsCredentials(final HttpServletRequest request) {
        final String code = request.getParameter("code");
        final String idToken = request.getParameter("id_token");
        final String accessToken = request.getParameter("access_token");
        final String signedRequest = request.getParameter("signed_request");
        return hasText(code) || hasText(idToken) || hasText(accessToken) || hasText(signedRequest);
    }

    private boolean authenticationWasSuccessful(
            final HttpServletRequest request,
            final HttpServletResponse response) throws IOException {
        final String origin = FilenameUtils.getName(request.getRequestURI());
        final String code = request.getParameter("code");
        final String idToken = request.getParameter("id_token");
        final String accessToken = request.getParameter("access_token");
        final String signedRequest = request.getParameter("signed_request");

        final String redirectUrl = request.getRequestURL().toString();
        final ExternalOAuthCodeToken codeToken = new ExternalOAuthCodeToken(code,
                origin,
                redirectUrl,
                idToken,
                accessToken,
                signedRequest,
                new UaaAuthenticationDetails(request));
        try {
            final Authentication authentication =
                    externalOAuthAuthenticationManager.authenticate(codeToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            ofNullable(successHandler).ifPresent(handler ->
                    handler.setSavedAccountOptionCookie(request, response, authentication)
            );
            // TODO: :eyes_narrowed:
            // should be an instance of AuthenticationException
            // but can we trust it?
        } catch (Exception ex) {
            logger.error("ExternalOAuth Authentication exception", ex);
            String message = ex.getMessage();
            if (!hasText(message)) {
                message = ex.getClass().getSimpleName();
            }
            final String errorMessage = "There was an error when authenticating against the external identity provider: %s".formatted(message);
            request.getSession().setAttribute("oauth_error", errorMessage);
            response.sendRedirect(request.getContextPath() + "/oauth_error");
            return false;
        }
        return true;
    }
}
