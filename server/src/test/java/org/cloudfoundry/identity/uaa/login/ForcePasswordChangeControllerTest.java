package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@ExtendWith(PollutionPreventionExtension.class)
@SpringJUnitConfig(classes = {ThymeleafAdditional.class, ThymeleafConfig.class})
class ForcePasswordChangeControllerTest extends TestClassNullifier {

    private MockMvc mockMvc;
    private ResourcePropertySource mockResourcePropertySource;
    private UaaAuthentication mockUaaAuthentication;

    @BeforeEach
    void beforeEach() {
        mockResourcePropertySource = mock(ResourcePropertySource.class);
        ForcePasswordChangeController controller = new ForcePasswordChangeController(
                mockResourcePropertySource,
                mock(ResetPasswordService.class),
                new IdentityZoneManagerImpl()
        );
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setViewResolvers(getResolver())
                .build();

        mockUaaAuthentication = mock(UaaAuthentication.class);
        UaaPrincipal mockUaaPrincipal = mock(UaaPrincipal.class);
        when(mockUaaAuthentication.getPrincipal()).thenReturn(mockUaaPrincipal);
        when(mockUaaPrincipal.getEmail()).thenReturn("mail");
        SecurityContextHolder.getContext().setAuthentication(mockUaaAuthentication);
    }

    @Test
    void forcePasswordChange() throws Exception {
        mockMvc.perform(get("/force_password_change"))
                .andExpect(status().isOk())
                .andExpect(view().name("force_password_change"))
                .andExpect(model().attribute("email", "mail"));
    }

    @Test
    void redirectToLogInIfPasswordIsNotExpired() throws Exception {
        mockMvc.perform(get("/force_password_change"))
                .andExpect(status().isOk())
                .andExpect(view().name("force_password_change"));
    }

    @Test
    void handleForcePasswordChange() throws Exception {
        mockMvc.perform(
                        post("/uaa/force_password_change")
                                .param("password", "pwd")
                                .param("password_confirmation", "pwd")
                                .contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/force_password_change_completed"));
        verify(mockUaaAuthentication, times(1)).setAuthenticatedTime(anyLong());
    }

    @Test
    void handleForcePasswordChangeWithRedirect() throws Exception {
        mockMvc.perform(
                        post("/force_password_change")
                                .param("password", "pwd")
                                .param("password_confirmation", "pwd"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/force_password_change_completed"));
    }

    @Test
    void passwordAndConfirmAreDifferent() throws Exception {
        when(mockResourcePropertySource.getProperty("force_password_change.form_error")).thenReturn("Passwords must match and not be empty.");
        mockMvc.perform(
                        post("/force_password_change")
                                .param("password", "pwd")
                                .param("password_confirmation", "nopwd"))
                .andExpect(status().isUnprocessableEntity());
    }
}
