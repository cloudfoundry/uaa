/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.LinkedHashSet;
import java.util.List;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.ChangePasswordController;
import org.cloudfoundry.identity.uaa.account.ChangePasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaa;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class ChangePasswordControllerTest extends TestClassNullifier {
    private MockMvc mockMvc;
    private ChangePasswordService changePasswordService;
    private UaaAuthentication authentication;
    private List<String> authMethods;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        changePasswordService = mock(ChangePasswordService.class);
        ChangePasswordController controller = new ChangePasswordController(changePasswordService);

        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setViewResolvers(getResolver())
                .build();

        authentication = new UaaAuthentication(
            new UaaPrincipal("id", "bob", "bob@bob.bob", UAA, null, IdentityZone.getUaaZoneId()),
            asList(UaaAuthority.UAA_USER),
            new UaaAuthenticationDetails(false, null, UAA, "12345")
        );
        authMethods = asList("pwd", "mfa", "otp");
        authentication.setAuthenticationMethods(new LinkedHashSet<>(authMethods));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void changePasswordPage_RendersChangePasswordPage() throws Exception {
        mockMvc.perform(get("/change_password"))
                .andExpect(status().isOk())
                .andExpect(view().name("change_password"));
    }

    @Test
    public void changePassword_Returns302Found_SuccessfullyChangedPassword() throws Exception {
        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "new secret");
        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));

        verify(changePasswordService).changePassword("bob", "secret", "new secret");
        Authentication afterAuth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(((UaaAuthentication)afterAuth).getAuthenticationMethods(), containsInAnyOrder(authMethods.toArray()));
        assertSame(authentication, afterAuth);
    }

    @Test
    public void changePassword_ConfirmationPasswordDoesNotMatch() throws Exception {
        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "newsecret");
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("change_password"))
                .andExpect(model().attribute("message_code", "form_error"));

        verifyZeroInteractions(changePasswordService);
    }

    @Test
    public void changePassword_PasswordPolicyViolationReported() throws Exception {
        doThrow(new InvalidPasswordException(asList("Msg 2b", "Msg 1b"))).when(changePasswordService).changePassword("bob", "secret", "new secret");

        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "new secret");
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("change_password"))
                .andExpect(model().attribute("message", "Msg 1b Msg 2b"));
    }

    @Test
    public void changePassword_Returns401Unauthorized_WrongCurrentPassword() throws Exception {
        doThrow(new BadCredentialsException("401 Unauthorized")).when(changePasswordService).changePassword("bob", "wrong", "new secret");

        MockHttpServletRequestBuilder post = createRequest("wrong", "new secret", "new secret");
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("change_password"))
                .andExpect(model().attribute("message_code", "unauthorized"));
    }

    @Test
    public void changePassword_PasswordNoveltyViolationReported_NewPasswordSameAsCurrentPassword() throws Exception {
        doThrow(new InvalidPasswordException("Your new password cannot be the same as the old password.")).when(changePasswordService).changePassword("bob", "secret", "new secret");

        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "new secret");
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("change_password"))
            .andExpect(model().attribute("message", "Your new password cannot be the same as the old password."));
    }

    private MockHttpServletRequestBuilder createRequest(String currentPassword, String newPassword, String confirmPassword) {
        return post("/change_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("current_password", currentPassword)
            .param("new_password", newPassword)
            .param("confirm_password", confirmPassword);
    }
}
