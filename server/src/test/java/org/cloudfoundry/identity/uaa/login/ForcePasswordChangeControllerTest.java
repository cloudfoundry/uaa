package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.cloudfoundry.identity.uaa.login.ForcePasswordChangeController.FORCE_PASSWORD_EXPIRED_USER;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class ForcePasswordChangeControllerTest  extends TestClassNullifier {

    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        ForcePasswordChangeController controller = new ForcePasswordChangeController();
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
                .param("password_conf", "pwd"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    public void testHandleForcePasswordChange() throws Exception {
        MockHttpSession session = getMockHttpSessionWithUser();
        mockMvc.perform(
            post("/force_password_change")
                .session(session)
                .param("password","pwd")
                .param("password_conf", "pwd"))
                .andExpect(status().isOk());
    }

    @Test
    public void testPasswordAndConfirmAreDifferent() throws Exception {
        MockHttpSession session = getMockHttpSessionWithUser();
        mockMvc.perform(
            post("/force_password_change")
                .session(session)
                .param("password","pwd")
                .param("password_conf", "nopwd"))
            .andExpect(status().isUnprocessableEntity());
    }
}