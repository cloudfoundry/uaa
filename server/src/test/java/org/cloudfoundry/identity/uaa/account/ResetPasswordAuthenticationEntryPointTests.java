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

package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation.PasswordConfirmationException;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Arrays;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ResetPasswordAuthenticationEntryPointTests {

    ResetPasswordAuthenticationEntryPoint entryPoint;
    private String email;
    private String code;
    private String password;
    private String passwordConfirmation;
    private String messageCode;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private RequestDispatcher requestDispatcher;

    @Before
    public void setup() throws Exception {
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        requestDispatcher = mock(RequestDispatcher.class);

        email = "test@test.org";
        code = "12345";
        password = "mypassword";
        passwordConfirmation = "mypassword";
        messageCode = "form_error";

        when(request.getParameter("email")).thenReturn(email);
        when(request.getParameter("code")).thenReturn(code);
        when(request.getParameter("password")).thenReturn(password);
        when(request.getParameter("password_confirmation")).thenReturn(passwordConfirmation);
        when(request.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);

        entryPoint = new ResetPasswordAuthenticationEntryPoint();
    }

    @Test
    public void test_invalid_password_match() throws Exception {
        PasswordConfirmationException pe = new PasswordConfirmationException(messageCode, email);
        BadCredentialsException be = new BadCredentialsException("", pe);

        entryPoint.commence(request, response, be);

        verify(request, times(1)).getRequestDispatcher(eq("/reset_password"));
        verify(request, times(1)).setAttribute(eq("message_code"), eq(messageCode));

        verify(requestDispatcher, timeout(1)).forward(any(request.getClass()), same(response));
        verify(response, times(1)).setStatus(eq(HttpStatus.UNPROCESSABLE_ENTITY.value()));
    }


    @Test
    public void test_when_uaa_exception() throws Exception {
        UaaException e = new UaaException(messageCode);
        InternalAuthenticationServiceException be = new InternalAuthenticationServiceException("", e);

        entryPoint.commence(request, response, be);

        verify(request, times(1)).getRequestDispatcher(eq("/forgot_password"));
        verify(request, times(1)).setAttribute(eq("message_code"), eq("bad_code"));
        verify(requestDispatcher, timeout(1)).forward(any(request.getClass()), same(response));
        verify(response, times(1)).setStatus(eq(HttpStatus.UNPROCESSABLE_ENTITY.value()));
    }

    @Test
    public void test_when_invalid_password_exception() throws Exception {
        InvalidPasswordException pe = new InvalidPasswordException(Arrays.asList("one","two"));
        BadCredentialsException be = new BadCredentialsException("", pe);

        entryPoint.commence(request, response, be);

        verify(request, times(1)).getRequestDispatcher(eq("/reset_password"));
        verify(request, times(1)).setAttribute(eq("message"), eq(pe.getMessagesAsOneString()));

        verify(requestDispatcher, timeout(1)).forward(any(request.getClass()), same(response));
        verify(response, times(1)).setStatus(eq(HttpStatus.UNPROCESSABLE_ENTITY.value()));
    }

}
