/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Filter which processes and authenticates a client based on
 * parameters client_id and client_secret
 * It sets the authentication to a client only
 * Oauth2Authentication object as that is expected by
 * the LoginAuthenticationManager.
 */
public class LoginClientParametersAuthenticationFilter extends AbstractClientParametersAuthenticationFilter {

    public LoginClientParametersAuthenticationFilter(
            @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager
    ) {
        this.setClientAuthenticationManager(authenticationManager);
    }

    @Override
    public void wrapClientCredentialLogin(HttpServletRequest req, HttpServletResponse res, Map<String, String> loginInfo, String clientId) {
        if (loginInfo.isEmpty()) {
            throw new BadCredentialsException("Request does not contain credentials.");
        } else if (clientAuthenticationManager == null || loginInfo.get(CLIENT_ID) == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Insufficient resources to perform client authentication. AuthMgr:{}; clientId:{}", clientAuthenticationManager, UaaStringUtils.getCleanedUserControlString(clientId));
            }
            throw new BadCredentialsException("Request does not contain client credentials.");
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Located credentials in request, with keys: {}", UaaStringUtils.getCleanedUserControlString(loginInfo.keySet().toString()));
            }

            doClientCredentialLogin(req, loginInfo, clientId);
        }
    }
}
