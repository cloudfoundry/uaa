package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.cloudfoundry.identity.uaa.login.ForcePasswordChangeController.FORCE_PASSWORD_EXPIRED_USER;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.SAVED_REQUEST_SESSION_ATTRIBUTE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {ThymeleafAdditional.class,ThymeleafConfig.class})
public class ForcePasswordChangeControllerTest  extends TestClassNullifier {

    private MockMvc mockMvc;
    private ResetPasswordService resetPasswordService;
    private ResourcePropertySource resourcePropertySource;
    private AccountSavingAuthenticationSuccessHandler successHandler = new AccountSavingAuthenticationSuccessHandler();

    @Before
    public void setUp() throws Exception {
        ForcePasswordChangeController controller = new ForcePasswordChangeController();
        resetPasswordService = mock(ResetPasswordService.class);
        controller.setResetPasswordService(resetPasswordService);
        resourcePropertySource = mock(ResourcePropertySource.class);
        controller.setResourcePropertySource(resourcePropertySource);
        successHandler = mock(AccountSavingAuthenticationSuccessHandler.class);
        controller.setSuccessHandler(successHandler);
        mockMvc = MockMvcBuilders
            .standaloneSetup(controller)
            .setViewResolvers(getResolver())
            .build();
    }

    @Test
    public void testForcePasswordChange() throws Exception {
        MockHttpSession session = getMockHttpSessionWithUser();
        mockMvc.perform(get("/force_password_change")
            .session(session))
            .andExpect(status().isOk())
            .andExpect(view().name("force_password_change"))
            .andExpect(model().attribute("email", "mail"));
    }

    private MockHttpSession getMockHttpSessionWithUser() {
        MockHttpSession session = new MockHttpSession();
        UaaAuthentication auth = mock(UaaAuthentication.class);
        UaaPrincipal principal = mock(UaaPrincipal.class);
        when(auth.getPrincipal()).thenReturn(principal);
        when(principal.getEmail()).thenReturn("mail");
        session.setAttribute(FORCE_PASSWORD_EXPIRED_USER, auth);
        return session;
    }

    @Test
    public void testRedirectToLogInIfPasswordIsNotExpired() throws Exception {
        mockMvc.perform(get("/force_password_change"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testHandleForcePasswordChangeNoSession() throws Exception {
        mockMvc.perform(
            post("/force_password_change")
                .param("password","pwd")
                .param("password_confirmation", "pwd"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testHandleForcePasswordChange() throws Exception {
        MockHttpSession session = getMockHttpSessionWithUser();
        mockMvc.perform(
            post("/uaa/force_password_change")
                .session(session)
                .param("password","pwd")
                .param("password_confirmation", "pwd")
                .contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/"));
    }

    @Test
    public void testHandleForcePasswordChangeWithRedirect() throws Exception {
        MockHttpSession session = getMockHttpSessionWithUser();
        SavedRequest savedRequest = mock(SavedRequest.class);
        String redirectUrl = "/test";
        when(savedRequest.getRedirectUrl()).thenReturn(redirectUrl);
        session.setAttribute(SAVED_REQUEST_SESSION_ATTRIBUTE, savedRequest);

        mockMvc.perform(
            post("/force_password_change")
                .session(session)
                .param("password","pwd")
                .param("password_confirmation", "pwd"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(redirectUrl));
    }

    @Test
    public void testPasswordAndConfirmAreDifferent() throws Exception {
        MockHttpSession session = getMockHttpSessionWithUser();
        when(resourcePropertySource.getProperty("force_password_change.form_error")).thenReturn("Passwords must match and not be empty.");
        mockMvc.perform(
            post("/force_password_change")
                .session(session)
                .param("password","pwd")
                .param("password_confirmation", "nopwd"))
            .andExpect(status().isUnprocessableEntity());
    }
}
