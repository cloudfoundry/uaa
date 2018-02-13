/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaCodeException;
import org.cloudfoundry.identity.uaa.mfa.exception.MissingMfaCodeException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;

public class StatelessMfaAuthenticationFilter extends OncePerRequestFilter {

    private final UserGoogleMfaCredentialsProvisioning provisioning;
    private final Set<String> supportedGrantTypes;
    private final MfaProviderProvisioning mfaProvider;

    public StatelessMfaAuthenticationFilter(UserGoogleMfaCredentialsProvisioning provisioning,
                                            Set<String> supportedGrantTypes,
                                            MfaProviderProvisioning mfaProvider) {
        this.provisioning = provisioning;
        this.supportedGrantTypes = supportedGrantTypes;
        this.mfaProvider = mfaProvider;
    }

    public boolean isGrantTypeSupported(String type) {
        return supportedGrantTypes.contains(type);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        try {
            checkMfaCode(request);
            filterChain.doFilter(request, response);
        } catch (MissingMfaCodeException | UserMfaConfigDoesNotExistException e) {
            handleException(new JsonError(400, "invalid_request", e.getMessage()), response);
        } catch (InvalidMfaCodeException e) {
            handleException(new JsonError(401, "unauthorized", "Bad credentials"), response);
        }
    }

    protected void handleException(JsonError error, HttpServletResponse response) throws IOException {
        response.setStatus(error.getStatus());
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(JsonUtils.writeValueAsString(error));
    }

    protected void checkMfaCode(HttpServletRequest request)
        throws ServletException, IOException {
        IdentityZone zone = IdentityZoneHolder.get();
        if (isGrantTypeSupported(request.getParameter(GRANT_TYPE)) && isMfaEnabled(zone)) {
            UaaAuthentication authentication = getAuthentication();
            MfaProvider provider = null;
            try {
                provider = mfaProvider.retrieveByName(zone.getConfig().getMfaConfig().getProviderName(), zone.getId());
            } catch (EmptyResultDataAccessException x) {
                throw new ProviderNotFoundException("Unable to find MFA provider for zone:"+zone.getSubdomain());
            }
            Integer code = getMfaCode(request);
            UserGoogleMfaCredentials credentials = provisioning.getUserGoogleMfaCredentials(authentication.getPrincipal().getId(), provider.getId());
            if (credentials == null) {
                throw new UserMfaConfigDoesNotExistException("User must register a multi-factor authentication token");
            }
            if (!provisioning.isValidCode(credentials, code)) {
                throw new InvalidMfaCodeException("Invalid multi-factor authentication code");
            }
            HashSet<String> authMethods = new HashSet<>(authentication.getAuthenticationMethods());
            authMethods.add("otp");
            authMethods.add("mfa");
            authentication.setAuthenticationMethods(authMethods);
        }
    }

    private Integer getMfaCode(HttpServletRequest request) {
        String code = request.getParameter("mfaCode");
        if (StringUtils.isEmpty(code)) {
            throw new MissingMfaCodeException("A multi-factor authentication code is required to complete the request");
        }
        try {
            return Integer.valueOf(code);
        } catch (NumberFormatException x) {
            throw new InvalidMfaCodeException("Bad credentials");
        }
    }

    private boolean isMfaEnabled(IdentityZone zone) {
        return zone.getConfig().getMfaConfig().isEnabled();
    }

    private UaaAuthentication getAuthentication() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new InsufficientAuthenticationException("User authentication missing");
        } else if (! (auth instanceof OAuth2Authentication)) {
            throw new InsufficientAuthenticationException("Unrecognizable authentication");
        }
        Authentication userAuth = ((OAuth2Authentication)auth).getUserAuthentication();
        if (! (userAuth instanceof UaaAuthentication)) {
            throw new InsufficientAuthenticationException("Unrecognizable user authentication");
        }
        return (UaaAuthentication)userAuth;
    }

    public Set<String> getSupportedGrantTypes() {
        return Collections.unmodifiableSet(supportedGrantTypes);
    }

    public static class JsonError {
        private final int status;
        private final String error;
        private final String error_description;

        private JsonError(int status, String error, String error_description) {
            this.status = status;
            this.error = error;
            this.error_description = error_description;
        }

        public String getError() {
            return error;
        }

        public String getError_description() {
            return error_description;
        }

        public int getStatus() {
            return status;
        }
    }
}
