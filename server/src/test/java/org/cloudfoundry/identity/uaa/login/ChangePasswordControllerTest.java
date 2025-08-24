package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.ChangePasswordController;
import org.cloudfoundry.identity.uaa.account.ChangePasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.TestClassNullifier.getResolver;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@ExtendWith(PollutionPreventionExtension.class)
class ChangePasswordControllerTest {
    private MockMvc mockMvc;
    private ChangePasswordService changePasswordService;
    private UaaAuthentication authentication;
    private List<String> authMethods;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        changePasswordService = mock(ChangePasswordService.class);
        ChangePasswordController controller = new ChangePasswordController(changePasswordService);

        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setViewResolvers(getResolver())
                .build();

        authentication = new UaaAuthentication(
                new UaaPrincipal("id", "bob", "bob@bob.bob", UAA, null, IdentityZone.getUaaZoneId()),
                Collections.singletonList(UaaAuthority.UAA_USER),
                new UaaAuthenticationDetails(false, null, UAA, "12345")
        );
        authMethods = asList("pwd", "otp");
        authentication.setAuthenticationMethods(new LinkedHashSet<>(authMethods));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void changePasswordPage_RendersChangePasswordPage() throws Exception {
        mockMvc.perform(get("/change_password"))
                .andExpect(status().isOk())
                .andExpect(view().name("change_password"));
    }

    @Test
    void changePassword_Returns302Found_SuccessfullyChangedPassword() throws Exception {
        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "new secret");
        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));

        verify(changePasswordService).changePassword("bob", "secret", "new secret");
        Authentication afterAuth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(((UaaAuthentication) afterAuth).getAuthenticationMethods()).containsExactlyInAnyOrderElementsOf(authMethods);
        assertThat(afterAuth).isSameAs(authentication);
    }

    @Test
    void changePassword_ConfirmationPasswordDoesNotMatch() throws Exception {
        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "newsecret");
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("change_password"))
                .andExpect(model().attribute("message_code", "form_error"));

        verifyNoInteractions(changePasswordService);
    }

    @Test
    void changePassword_PasswordPolicyViolationReported() throws Exception {
        doThrow(new InvalidPasswordException(asList("Msg 2b", "Msg 1b"))).when(changePasswordService).changePassword(
                "bob",
                "secret",
                "new secret");

        MockHttpServletRequestBuilder post = createRequest("secret", "new secret", "new secret");
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("change_password"))
                .andExpect(model().attribute("message", "Msg 1b Msg 2b"));
    }

    @Test
    void changePassword_Returns401Unauthorized_WrongCurrentPassword() throws Exception {
        doThrow(new BadCredentialsException("401 Unauthorized")).when(changePasswordService).changePassword("bob",
                "wrong",
                "new secret");

        MockHttpServletRequestBuilder post = createRequest("wrong", "new secret", "new secret");
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("change_password"))
                .andExpect(model().attribute("message_code", "unauthorized"));
    }

    @Test
    void changePassword_PasswordNoveltyViolationReported_NewPasswordSameAsCurrentPassword() throws Exception {
        doThrow(new InvalidPasswordException("Your new password cannot be the same as the old password.")).when(
                changePasswordService).changePassword("bob", "secret", "new secret");

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
