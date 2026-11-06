/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class ResetPasswordAuthenticationFilter extends OncePerRequestFilter {
    private final ResetPasswordService service;
    private final AuthenticationEntryPoint entryPoint;
    private final ExpiringCodeStore expiringCodeStore;
    public static final String RESET_PASSWORD_URL = "/reset_password.do";
    private static final String INVALID_CODE_MESSAGE = "Sorry, your reset password link is no longer valid. Please request a new one";
    private static final RequestMatcher matcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, RESET_PASSWORD_URL);

    public ResetPasswordAuthenticationFilter(
            ResetPasswordService service,
            AuthenticationEntryPoint entryPoint,
            ExpiringCodeStore expiringCodeStore) {
        this.service = service;
        this.entryPoint = entryPoint;
        this.expiringCodeStore = expiringCodeStore;
    }

    public ResetPasswordAuthenticationFilter(
            ResetPasswordService service,
            ExpiringCodeStore expiringCodeStore) {
        this(service, new ResetPasswordAuthenticationEntryPoint(), expiringCodeStore);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!matcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        String email = request.getParameter("email");
        String code = request.getParameter("code");
        String password = request.getParameter("password");
        String passwordConfirmation = request.getParameter("password_confirmation");

        PasswordConfirmationValidation validation = new PasswordConfirmationValidation(email, password, passwordConfirmation);
        ExpiringCode expiringCode = null;
        try {
            expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
            validation.throwIfNotValid();
            if (expiringCode == null) {
                throw new InvalidCodeException("invalid_code", INVALID_CODE_MESSAGE, 422);
            }
            ResetPasswordService.ResetPasswordResponse resetPasswordResponse = service.resetPassword(expiringCode, password);
            String redirectUri = resetPasswordResponse.getRedirectUri();
            if (!StringUtils.hasText(redirectUri) || "home".equals(redirectUri)) {
                response.sendRedirect(request.getContextPath() + "/login?success=password_reset");
            } else {
                UaaSavedRequestAwareAuthenticationSuccessHandler.saveTrustedRedirect(
                        request.getSession(),
                        redirectUri);
                response.sendRedirect(request.getContextPath() + "/login?success=password_reset&form_redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8));
            }
        } catch (InvalidPasswordException e) {
            commenceWithRefreshedCode(request, response, expiringCode, new BadCredentialsException(e.getMessagesAsOneString(), e));
        } catch (UaaException e) {
            entryPoint.commence(request, response, new InternalAuthenticationServiceException(e.getMessage(), e));
        } catch (PasswordConfirmationException pe) {
            commenceWithRefreshedCode(request, response, expiringCode, new BadCredentialsException("Password did not pass validation.", pe));
        }
    }

    private void commenceWithRefreshedCode(HttpServletRequest request, HttpServletResponse response, ExpiringCode expiringCode, AuthenticationException failure) throws IOException, ServletException {
        if (expiringCode != null) {
            try {
                ExpiringCode newCode = expiringCodeStore.generateCode(expiringCode.getData(), expiringCode.getExpiresAt(), expiringCode.getIntent(), IdentityZoneHolder.get().getId());
                request.setAttribute("code", newCode.getCode());
            } catch (IllegalArgumentException _) {
                // the code expired while the password was checked, so there is no code left to submit again
                InvalidCodeException expired = new InvalidCodeException("invalid_code", INVALID_CODE_MESSAGE, 422);
                entryPoint.commence(request, response, new InternalAuthenticationServiceException(expired.getMessage(), expired));
                return;
            }
        }
        entryPoint.commence(request, response, failure);
    }

}
