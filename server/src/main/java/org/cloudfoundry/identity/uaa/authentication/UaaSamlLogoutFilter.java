package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class UaaSamlLogoutFilter extends LogoutFilter {

    public UaaSamlLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
        super(logoutSuccessHandler, handlers);
        setFilterProcessesUrl("/logout.do");
    }

    protected boolean isGlobalLogout(HttpServletRequest request, Authentication auth) {
        try {
            IdentityProviderMetadata idp = null;
            List<Endpoint> singleLogoutServices = idp.getIdentityProvider().getSingleLogoutService();
            return singleLogoutServices.size() != 0;
        } catch (Exception e) {
            logger.debug("Error processing metadata", e);
            return false;
        }
    }

    @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getCredentials() instanceof SamlAuthentication && super.requiresLogout(request, response);
    }
}
