/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

import static java.util.Arrays.stream;
import static java.util.Collections.EMPTY_SET;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addFragmentComponent;
import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.addQueryParameter;
import static org.springframework.util.StringUtils.hasText;


public class AuthorizePromptNoneEntryPoint implements AuthenticationEntryPoint {

    private static Log logger = LogFactory.getLog(AuthorizePromptNoneEntryPoint.class);

    private final AuthenticationFailureHandler failureHandler;
    private final ClientServicesExtension clientDetailsService;
    private final RedirectResolver redirectResolver;

    public AuthorizePromptNoneEntryPoint(AuthenticationFailureHandler failureHandler,
                                         ClientServicesExtension clientDetailsService,
                                         RedirectResolver redirectResolver) {
        this.failureHandler = failureHandler;
        this.clientDetailsService = clientDetailsService;
        this.redirectResolver = redirectResolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        String clientId = request.getParameter(OAuth2Utils.CLIENT_ID);
        String redirectUri = request.getParameter(OAuth2Utils.REDIRECT_URI);
        String[] responseTypes = ofNullable(request.getParameter(OAuth2Utils.RESPONSE_TYPE)).map(rt -> rt.split(" ")).orElse(new String[0]);

        //client_id is a required parameter
        if (!hasText(clientId)) {
            logger.debug("[prompt=none] Missing client_id parameter");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        ClientDetails client;
        try {
            client = clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
        } catch (ClientRegistrationException e) {
            logger.debug("[prompt=none] Unable to look up client for client_id="+clientId, e);
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        Set<String> redirectUris = ofNullable(client.getRegisteredRedirectUri()).orElse(EMPTY_SET);

        //if the client doesn't have a redirect uri set, the parameter is required.
        if (redirectUris.size()==0 && !hasText(redirectUri)) {
            logger.debug("[prompt=none] Missing redirect_uri");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        String resolvedRedirect;
        try {
            resolvedRedirect = redirectResolver.resolveRedirect(redirectUri, client);
        } catch (RedirectMismatchException rme) {
            logger.debug("[prompt=none] Invalid redirect " + redirectUri + " did not match one of the registered values");
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return;
        }

        failureHandler.onAuthenticationFailure(request, response, authException);
        boolean implicit = stream(responseTypes).noneMatch("code"::equalsIgnoreCase);
        String redirectLocation = implicit ? addFragmentComponent(resolvedRedirect, "error=login_required") : addQueryParameter(resolvedRedirect, "error", "login_required");
        response.sendRedirect(redirectLocation);
    }
}
