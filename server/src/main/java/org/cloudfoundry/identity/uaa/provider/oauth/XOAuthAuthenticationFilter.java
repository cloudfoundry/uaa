package org.cloudfoundry.identity.uaa.provider.oauth;

import org.apache.commons.httpclient.util.URIUtil;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import static java.util.Optional.ofNullable;
import static org.springframework.util.StringUtils.hasText;

public class XOAuthAuthenticationFilter implements Filter {

    private static Logger logger = LoggerFactory.getLogger(XOAuthAuthenticationFilter.class);

    private final XOAuthAuthenticationManager xOAuthAuthenticationManager;
    private final AccountSavingAuthenticationSuccessHandler successHandler;

    public XOAuthAuthenticationFilter(
            final XOAuthAuthenticationManager xOAuthAuthenticationManager,
            final AccountSavingAuthenticationSuccessHandler successHandler) {
        this.xOAuthAuthenticationManager = xOAuthAuthenticationManager;
        this.successHandler = successHandler;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(
            final ServletRequest servletRequest,
            final ServletResponse servletResponse,
            final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (containsCredentials(request)) {
            if (authenticationWasSuccessful(request, response)) {
                chain.doFilter(request, response);
            }
        } else {
            request.getRequestDispatcher("/login_implicit").forward(request, response);
        }
    }

    public boolean containsCredentials(final HttpServletRequest request) {
        final String code = request.getParameter("code");
        final String idToken = request.getParameter("id_token");
        final String accessToken = request.getParameter("access_token");
        final String signedRequest = request.getParameter("signed_request");
        return hasText(code) || hasText(idToken) || hasText(accessToken) || hasText(signedRequest);
    }

    private boolean authenticationWasSuccessful(
            final HttpServletRequest request,
            final HttpServletResponse response) throws IOException {
        final String origin = URIUtil.getName(String.valueOf(request.getRequestURL()));
        final String code = request.getParameter("code");
        final String idToken = request.getParameter("id_token");
        final String accessToken = request.getParameter("access_token");
        final String signedRequest = request.getParameter("signed_request");

        final String redirectUrl = request.getRequestURL().toString();
        final XOAuthCodeToken codeToken = new XOAuthCodeToken(code,
                origin,
                redirectUrl,
                idToken,
                accessToken,
                signedRequest,
                new UaaAuthenticationDetails(request));
        try {
            final Authentication authentication = xOAuthAuthenticationManager.authenticate(codeToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            ofNullable(successHandler).ifPresent(handler ->
                    handler.setSavedAccountOptionCookie(request, response, authentication)
            );
        } catch (Exception ex) {
            logger.error("XOauth Authentication exception", ex);
            String message = ex.getMessage();
            if (!hasText(message)) {
                message = ex.getClass().getSimpleName();
            }
            final String errorMessage = URLEncoder.encode("There was an error when authenticating against the external identity provider: " + message, StandardCharsets.UTF_8);
            response.sendRedirect(request.getContextPath() + "/oauth_error?error=" + errorMessage);
            return false;
        }
        return true;
    }
}
