/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;


import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutHandler;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ZoneAwareWhitelistLogoutHandler implements LogoutSuccessHandler {

    private final MultitenantClientServices clientDetailsService;
    private final ExternalOAuthLogoutHandler externalOAuthLogoutHandler;
    private final KeyInfoService keyInfoService;

    public ZoneAwareWhitelistLogoutHandler(MultitenantClientServices clientDetailsService, ExternalOAuthLogoutHandler externalOAuthLogoutHandler,
        KeyInfoService keyInfoService) {
        this.clientDetailsService = clientDetailsService;
        this.externalOAuthLogoutHandler = externalOAuthLogoutHandler;
        this.keyInfoService = keyInfoService;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        AbstractExternalOAuthIdentityProviderDefinition oauthConfig = externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication);
        String logoutUrl = externalOAuthLogoutHandler.getLogoutUrl(oauthConfig);

        if (logoutUrl == null) {
            getZoneHandler().onLogoutSuccess(request, response, authentication);
        } else {
            externalOAuthLogoutHandler.onLogoutSuccess(request, response, authentication);
        }
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AbstractExternalOAuthIdentityProviderDefinition oauthConfig = externalOAuthLogoutHandler.getOAuthProviderForAuthentication(authentication);
        String logoutUrl = externalOAuthLogoutHandler.getLogoutUrl(oauthConfig);

        if (logoutUrl == null) {
            return getZoneHandler().determineTargetUrl(request, response);
        } else {
            return externalOAuthLogoutHandler.constructOAuthProviderLogoutUrl(request, logoutUrl, oauthConfig);
        }
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
        handler.setKeyInfoService(keyInfoService);
        return handler;
    }

}
