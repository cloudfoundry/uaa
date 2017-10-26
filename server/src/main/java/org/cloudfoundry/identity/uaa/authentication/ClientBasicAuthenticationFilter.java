/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import java.sql.Timestamp;
import java.util.Calendar;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * This class is an extension of Spring Framework BasicAuthenticationFilter that observes
 * the client lockout policy and throws ClientLockoutException when the client attempting
 * to authenticate is locked out.
 */
public class ClientBasicAuthenticationFilter extends BasicAuthenticationFilter {

    protected ClientDetailsService clientDetailsService;

    public ClientBasicAuthenticationFilter(AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint) {

        super(authenticationManager, authenticationEntryPoint);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
                    throws IOException, ServletException {
        try{
            String header = request.getHeader("Authorization");
            if (header == null || !header.startsWith("Basic ")) {
                chain.doFilter(request, response);
                return;
            }

            String[] decodedHeader = extractAndDecodeHeader(header, request);
            //Validate against client lockout policy
            String clientId = decodedHeader[0];

            //Validate against client secret expiration in the zone configured client secret policy
            Timestamp lastModified = (Timestamp) clientDetailsService.loadClientByClientId(clientId).getAdditionalInformation().get(ClientConstants.LAST_MODIFIED);
        } catch(BadCredentialsException e) {
            super.getAuthenticationEntryPoint().commence(request, response, e);
            return;
        } catch(ClientRegistrationException e) {
            logger.debug(e.getMessage());
        }
        //call parent class to authenticate
        super.doFilterInternal(request, response, chain);
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    private String[] extractAndDecodeHeader(String header, HttpServletRequest request)
            throws IOException {

        byte[] base64Token = header.substring(6).getBytes("UTF-8");
        byte[] decoded;
        try {
            decoded = Base64.decode(base64Token);
        }
        catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

        String token = new String(decoded, getCredentialsCharset(request));

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        return new String[] { token.substring(0, delim), token.substring(delim + 1) };
    }
}
