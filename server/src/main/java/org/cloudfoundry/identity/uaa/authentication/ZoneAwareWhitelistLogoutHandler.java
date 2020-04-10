package org.cloudfoundry.identity.uaa.authentication;


import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ZoneAwareWhitelistLogoutHandler implements LogoutSuccessHandler {

    private final MultitenantClientServices clientDetailsService;

    public ZoneAwareWhitelistLogoutHandler(MultitenantClientServices clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        getZoneHandler().onLogoutSuccess(request, response, authentication);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        return getZoneHandler().determineTargetUrl(request, response);
    }

    protected WhitelistLogoutHandler getZoneHandler() {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        if (config==null) {
            config = new IdentityZoneConfiguration();
        }
        WhitelistLogoutHandler handler = new WhitelistLogoutHandler(config.getLinks().getLogout().getWhitelist());
        handler.setTargetUrlParameter(config.getLinks().getLogout().getRedirectParameterName());
        handler.setDefaultTargetUrl(config.getLinks().getLogout().getRedirectUrl());
        handler.setAlwaysUseDefaultTargetUrl(config.getLinks().getLogout().isDisableRedirectParameter());
        handler.setClientDetailsService(clientDetailsService);
        return handler;
    }

}
