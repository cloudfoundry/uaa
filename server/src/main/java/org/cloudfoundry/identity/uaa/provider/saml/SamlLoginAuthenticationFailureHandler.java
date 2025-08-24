package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.cloudfoundry.identity.uaa.authentication.MalformedSamlResponseLogger;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;

/**
 * This class is used to provide OAuth error redirects when SAML login fails
 * with LoginSAMLException. Currently, the only scenario for this is when a
 * shadow account does not exist for the user and the IdP configuration does not
 * allow automatic creation of the shadow account.
 */
@Slf4j
public class SamlLoginAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    MalformedSamlResponseLogger malformedLogger = new MalformedSamlResponseLogger();

    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException exception) throws IOException, ServletException {

        String redirectTo = null;
        if (exception instanceof SamlLoginException) {
            redirectTo = handleSamlLoginException(request, response, exception);
        } else if (exception instanceof Saml2AuthenticationException) {
            malformedLogger.logMalformedResponse(request);
            redirectTo = handleSamlLoginException(request, response, exception);
        }

        if (redirectTo == null) {
            Throwable cause = exception.getCause();
            if (cause != null) {
                AuthenticationException e = new AuthenticationServiceException(cause.getMessage(), cause.getCause());
                logger.debug(cause);
                super.onAuthenticationFailure(request, response, e);
            } else {
                logger.debug(exception);
                super.onAuthenticationFailure(request, response, exception);
            }
        }
    }

    private String handleSamlLoginException(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        String redirectTo = null;

        HttpSession session = request.getSession();
        if (session != null) {
            DefaultSavedRequest savedRequest =
                    (DefaultSavedRequest) SessionUtils.getSavedRequestSession(session);
            if (savedRequest != null) {
                String[] redirectURI = savedRequest.getParameterMap().get("redirect_uri");

                if (redirectURI != null && redirectURI.length > 0) {
                    URI uri = URI.create(redirectURI[0]);
                    URIBuilder uriBuilder = new URIBuilder(uri);
                    uriBuilder.addParameter("error", "access_denied");
                    uriBuilder.addParameter("error_description", exception.getMessage());
                    redirectTo = uriBuilder.toString();

                    log.debug("Error redirect to: {}", redirectTo);
                    getRedirectStrategy().sendRedirect(request, response, redirectTo);
                }
            }
        }

        return redirectTo;
    }
}
