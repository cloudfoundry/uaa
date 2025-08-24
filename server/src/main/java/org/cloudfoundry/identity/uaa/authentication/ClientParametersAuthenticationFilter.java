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

import org.flywaydb.core.internal.util.StringUtils;
import org.springframework.http.MediaType;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Filter which processes and authenticates a client based on
 * parameters client_id and client_secret
 * It sets the authentication to a client only
 * Oauth2Authentication object as that is expected by
 * the LoginAuthenticationManager.
 *
 */
public class ClientParametersAuthenticationFilter extends AbstractClientParametersAuthenticationFilter {

    @Override
    public void wrapClientCredentialLogin(HttpServletRequest req, HttpServletResponse res, Map<String, String> loginInfo, String clientId) {
        if (!StringUtils.hasText(req.getHeader("Authorization")) && isUrlEncodedForm(req)) {
            doClientCredentialLogin(req, loginInfo, clientId);
        }
    }

    private boolean isUrlEncodedForm(HttpServletRequest req) {
        boolean isUrlEncodedForm = false;
        if (req.getHeader("Content-Type") != null) {
            isUrlEncodedForm = req.getHeader("Content-Type").startsWith(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        }
        return isUrlEncodedForm;
    }
}
