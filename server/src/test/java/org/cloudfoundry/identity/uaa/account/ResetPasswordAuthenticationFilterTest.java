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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.StringUtils;

class ResetPasswordAuthenticationFilterTest {

    private String password;
    private MockHttpServletRequest request;
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final ResetPasswordService service = mock(ResetPasswordService.class);
    private ScimUser user;
    private ResetPasswordService.ResetPasswordResponse resetPasswordResponse;
    private ResetPasswordAuthenticationFilter filter;
    private final AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
    private String email;

    @BeforeEach
    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @BeforeEach
    void setup() {
        var codeStore = new InMemoryExpiringCodeStore(new TimeServiceImpl());
        var code = codeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 10 * 60 * 1000), "", IdentityZoneHolder.get().getId()).getCode();

        password = "test";
        var passwordConfirmation = "test";
        email = "test@test.org";

        request = MockMvcRequestBuilders.post("/reset_password.do")
                .param("code", code)
                .param("password", password)
                .param("password_confirmation", passwordConfirmation)
                .param("email", email)
                .buildRequest(new MockServletContext());

        user = new ScimUser("id", "username", "first name", "last name");
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "/", null);
        filter = new ResetPasswordAuthenticationFilter(service, entryPoint, codeStore);
    }

    @Test
    void test_happy_day_password_reset() throws Exception {
        when(service.resetPassword(any(ExpiringCode.class), eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset(resetPasswordResponse.getRedirectUri());
    }

    @Test
    void happy_day_password_reset_with_redirect() throws Exception {
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "http://test.com", null);
        when(service.resetPassword(any(ExpiringCode.class), eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset(resetPasswordResponse.getRedirectUri());
    }

    @Test
    void happy_day_password_reset_with_null_redirect() throws Exception {
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, null, null);
        when(service.resetPassword(any(ExpiringCode.class), eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset(resetPasswordResponse.getRedirectUri());
    }

    @Test
    void happy_day_password_reset_with_home_redirect() throws Exception {
        resetPasswordResponse = new ResetPasswordService.ResetPasswordResponse(user, "home", null);
        when(service.resetPassword(any(ExpiringCode.class), eq(password))).thenReturn(resetPasswordResponse);
        happy_day_password_reset("");
    }

    public void happy_day_password_reset(String redirectUri) throws Exception {
        filter.doFilterInternal(request, response, chain);
        //do our assertion
        verify(service, times(1)).resetPassword(any(ExpiringCode.class), eq(password));
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        if (!StringUtils.hasText(redirectUri) || "home".equals(redirectUri)) {
            verify(response, times(1)).sendRedirect(request.getContextPath() + "/login?success=password_reset");
        } else {
            verify(response, times(1)).sendRedirect(request.getContextPath() + "/login?success=password_reset&form_redirect_uri=" + redirectUri);
        }
        verify(chain, times(0)).doFilter(any(), any());
    }

    @Test
    void invalid_password_confirmation() throws Exception {
        request.setParameter("password_confirmation", "invalid");
        Exception e = error_during_password_reset(PasswordConfirmationException.class);
        assertThat(e).isInstanceOf(AuthenticationException.class)
                .hasCauseInstanceOf(PasswordConfirmationException.class);

        PasswordConfirmationException pe = (PasswordConfirmationException) e.getCause();
        assertThat(pe.getMessageCode()).isEqualTo("form_error");
        assertThat(pe.getEmail()).isEqualTo(email);
    }

    @Test
    void error_during_password_reset_uaa_exception() throws Exception {
        UaaException failed = new UaaException("failed");
        when(service.resetPassword(any(ExpiringCode.class), anyString())).thenThrow(failed);
        error_during_password_reset(failed.getClass());
        verify(service, times(1)).resetPassword(any(ExpiringCode.class), eq(password));
    }

    @Test
    void error_during_password_reset_invalid_password_exception() throws Exception {
        InvalidPasswordException failed = new InvalidPasswordException("failed", HttpStatus.BAD_REQUEST);
        when(service.resetPassword(any(ExpiringCode.class), anyString())).thenThrow(failed);
        error_during_password_reset(failed.getClass());
        verify(service, times(1)).resetPassword(any(ExpiringCode.class), eq(password));
    }

    @Test
    void invalid_code_password_reset() throws Exception {
        request.setParameter("code", "invalid");
        error_during_password_reset(InvalidCodeException.class);
    }

    @Test
    void different_uri_skip_filter() throws ServletException, IOException {
        var request = MockMvcRequestBuilders.post("/wrong_url")
                .buildRequest(new MockServletContext());

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        verifyNoInteractions(service);
        verifyNoInteractions(entryPoint);
        verifyNoInteractions(response);
    }

    @Test
    void autowired_constructor() {
        var filter = new ResetPasswordAuthenticationFilter(service, new InMemoryExpiringCodeStore(new TimeServiceImpl()));
        var defaultEntryPoint = ReflectionTestUtils.getField(filter, "entryPoint");
        assertThat(defaultEntryPoint).isInstanceOf(ResetPasswordAuthenticationEntryPoint.class);
    }

    public AuthenticationException error_during_password_reset(Class<? extends Exception> failure) throws Exception {
        ArgumentCaptor<AuthenticationException> authenticationException = ArgumentCaptor.forClass(AuthenticationException.class);
        filter.doFilterInternal(request, response, chain);

        //do our assertion
        verify(entryPoint, times(1)).commence(same(request), same(response), authenticationException.capture());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        AuthenticationException exception = authenticationException.getValue();
        assertThat(exception.getCause().getClass()).isSameAs(failure);

        return exception;
    }
}
