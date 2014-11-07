/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class ResetPasswordControllerTest {
    private MockMvc mockMvc;
    private ResetPasswordService resetPasswordService;

    @Before
    public void setUp() throws Exception {
        resetPasswordService = Mockito.mock(ResetPasswordService.class);
        ResetPasswordController controller = new ResetPasswordController(resetPasswordService);

        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp");
        viewResolver.setSuffix(".jsp");
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setViewResolvers(viewResolver)
                .build();
    }

    @Test
    public void testForgotPasswordPage() throws Exception {
        mockMvc.perform(get("/forgot_password"))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot_password"));
    }

    @Test
    public void testForgotPassword() throws Exception {
        MockHttpServletRequestBuilder post = post("/forgot_password.do")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("email", "user@example.com");
        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=reset_password"));

        verify(resetPasswordService).forgotPassword(eq("user@example.com"));
    }

    @Test
    public void testForgotPasswordFormValidationFailure() throws Exception {
        MockHttpServletRequestBuilder post = post("/forgot_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("email", "notAnEmail");
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("message_code", "form_error"));

        verifyZeroInteractions(resetPasswordService);
    }

    @Test
    public void testInstructions() throws Exception {
        mockMvc.perform(get("/email_sent").param("code", "reset_password"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("code", "reset_password"));
    }

    @Test
    public void testResetPasswordPage() throws Exception {
        mockMvc.perform(get("/reset_password").param("email", "user@example.com").param("code", "secret_code"))
                .andExpect(status().isOk())
                .andExpect(view().name("reset_password"));
    }

    @Test
    public void testResetPasswordSuccess() throws Exception {
        MockHttpServletRequestBuilder post = post("/reset_password.do")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("code", "secret_code")
                .param("email", "foo@example.com")
                .param("password", "password")
                .param("password_confirmation", "password");
        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("home"))
                .andExpect(model().attributeDoesNotExist("code"))
                .andExpect(model().attributeDoesNotExist("password"))
                .andExpect(model().attributeDoesNotExist("password_confirmation"));

        verify(resetPasswordService).resetPassword("secret_code", "password");
    }

    @Test
    public void testResetPasswordFormValidationFailure() throws Exception {
        MockHttpServletRequestBuilder post = post("/reset_password.do")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("code", "123456")
                .param("email", "foo@example.com")
                .param("password", "pass")
                .param("password_confirmation", "word");

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("reset_password"))
                .andExpect(model().attribute("message_code", "form_error"))
                .andExpect(model().attribute("email", "foo@example.com"))
                .andExpect(model().attribute("code", "123456"));

        verifyZeroInteractions(resetPasswordService);
    }

    @Test
    public void testResetPasswordFormWithInvalidCode() throws Exception {
        Mockito.when(resetPasswordService.resetPassword("bad_code", "password")).thenThrow(new UaaException("Bad code!"));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("code", "bad_code")
                .param("email", "foo@example.com")
                .param("password", "password")
                .param("password_confirmation", "password");

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("forgot_password"))
                .andExpect(model().attribute("message_code", "bad_code"));

        verify(resetPasswordService).resetPassword("bad_code", "password");
    }
}
