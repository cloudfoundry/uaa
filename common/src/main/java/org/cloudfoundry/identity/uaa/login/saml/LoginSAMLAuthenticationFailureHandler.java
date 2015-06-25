package org.cloudfoundry.identity.uaa.login.saml;

import java.io.IOException;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

/**
 * This class is used to provide OAuth error redirects when SAML login fails
 * with LoginSAMLException. Currently, the only scenario for this is when a
 * shadow account does not exist for the user and the IdP configuration does not
 * allow automatic creation of the shadow account.
 * 
 */
public class LoginSAMLAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    private static final Log LOG = LogFactory.getLog(LoginSAMLAuthenticationFailureHandler.class);

    @Override
    public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
            final AuthenticationException exception) throws IOException, ServletException {

        String redirectTo = null;

        if (exception instanceof LoginSAMLException) {

            HttpSession session = request.getSession();
            if (session != null) {
                DefaultSavedRequest savedRequest =
                        (DefaultSavedRequest) session.getAttribute("SPRING_SECURITY_SAVED_REQUEST");
                if (savedRequest != null) {
                    String[] redirectURI = savedRequest.getParameterMap().get("redirect_uri");

                    if (redirectURI != null && redirectURI.length > 0) {
                        URI uri = URI.create(redirectURI[0]);
                        URIBuilder uriBuilder = new URIBuilder(uri);
                        uriBuilder.addParameter("error", "access_denied");
                        uriBuilder.addParameter("error_description", exception.getMessage());
                        redirectTo = uriBuilder.toString();

                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Error redirect to: " + redirectTo);
                        }

                        getRedirectStrategy().sendRedirect(request, response, redirectTo);
                    }
                }
            }
        }

        if (redirectTo == null) {
            super.onAuthenticationFailure(request, response, exception);
        }
    }
}
