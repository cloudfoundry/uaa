package org.cloudfoundry.identity.uaa.authentication;

import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class UaaSamlLogoutFilter extends SAMLLogoutFilter {


    public UaaSamlLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler... handlers) {
        super(logoutSuccessHandler, handlers, handlers);
        setFilterProcessesUrl("/logout.do");
    }

    @Override
    protected boolean isGlobalLogout(HttpServletRequest request, Authentication auth) {
        SAMLMessageContext context;
        try {
            SAMLCredential credential = (SAMLCredential) auth.getCredentials();
            request.setAttribute(SAMLConstants.LOCAL_ENTITY_ID, credential.getLocalEntityID());
            request.setAttribute(SAMLConstants.PEER_ENTITY_ID, credential.getRemoteEntityID());
            context = contextProvider.getLocalAndPeerEntity(request, null);
            IDPSSODescriptor idp = (IDPSSODescriptor) context.getPeerEntityRoleMetadata();
            List<SingleLogoutService> singleLogoutServices = idp.getSingleLogoutServices();
            return singleLogoutServices.size() != 0;
        } catch (MetadataProviderException e) {
            logger.debug("Error processing metadata", e);
            return false;
        }
    }

    @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.getCredentials() instanceof SAMLCredential && super.requiresLogout(request, response);
    }
}
