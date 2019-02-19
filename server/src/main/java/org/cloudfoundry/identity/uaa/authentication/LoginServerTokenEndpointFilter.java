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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;

public class LoginServerTokenEndpointFilter extends TokenEndpointAuthenticationFilter {


    private List<String> parameterNames = Collections.emptyList();
    /**
     * @param authenticationManager an AuthenticationManager for the incoming request
     */
    public LoginServerTokenEndpointFilter(AuthenticationManager authenticationManager, OAuth2RequestFactory oAuth2RequestFactory, List<String> addNewUserParameters) {
        super(authenticationManager, oAuth2RequestFactory);
        this.parameterNames = addNewUserParameters;
    }

    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
        super.onSuccessfulAuthentication(request, response, authResult);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof OAuth2Authentication) {
            ((OAuth2Authentication)auth).setAuthenticated(true);
        }
    }

    @Override
    protected Authentication extractCredentials(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (grantType != null && grantType.equals(GRANT_TYPE_PASSWORD)) {
            Map<String,String> loginInfo = new HashMap<>();
            for (String p : parameterNames) {
                String value = request.getParameter(p);
                if (StringUtils.hasText(value)) {
                    loginInfo.put(p, value);
                }
            }
            Authentication result = new AuthzAuthenticationRequest(loginInfo,new UaaAuthenticationDetails(request));
            return result;
        }
        return null;
    }
}
