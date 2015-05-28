package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class ChangeEmailControllerTest extends TestClassNullifier {

    private MockMvc mockMvc;
    private ChangeEmailService changeEmailService;
    private ChangeEmailController controller;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        changeEmailService = mock(ChangeEmailService.class);
        controller = new ChangeEmailController(changeEmailService);

        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp");
        viewResolver.setSuffix(".jsp");
        mockMvc = MockMvcBuilders
            .standaloneSetup(controller)
            .setViewResolvers(viewResolver)
            .build();
    }

    @Test
    public void testChangeEmailPage() throws Exception {
        setupSecurityContext();

        mockMvc.perform(get("/change_email"))
            .andExpect(status().isOk())
            .andExpect(view().name("change_email"))
            .andExpect(model().attribute("email", "user@example.com"));
    }

    @Test
    public void testChangeEmailPageWithClientId() throws Exception {
        setupSecurityContext();

        mockMvc.perform(get("/change_email?client_id=app"))
            .andExpect(status().isOk())
            .andExpect(view().name("change_email"))
            .andExpect(model().attribute("client_id", "app"))
            .andExpect(model().attribute("email", "user@example.com"));
    }

    @Test
    public void testChangeEmail() throws Exception {
        setupSecurityContext();

        MockHttpServletRequestBuilder post = post("/change_email.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("newEmail", "new@example.com")
            .param("client_id", "app");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=email_change"));

        Mockito.verify(changeEmailService).beginEmailChange("user-id-001", "bob", "new@example.com", "app");
    }

    @Test
    public void testChangeEmailWithUsernameConflict() throws Exception {
        setupSecurityContext();

        doThrow(new UaaException("username already exists", 409)).when(changeEmailService).beginEmailChange("user-id-001", "bob", "new@example.com", "");

        MockHttpServletRequestBuilder post = post("/change_email.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("newEmail", "new@example.com")
            .param("client_id", "");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("change_email"))
            .andExpect(model().attribute("error_message_code", "username_exists"))
            .andExpect(model().attribute("email", "user@example.com"));
    }

    @Test
    public void testNonUAAOriginUser() throws Exception {
        Authentication authentication = new UaaAuthentication(
            new UaaPrincipal("user-id-001", "bob", "user@example.com", "NON-UAA-origin ", null, IdentityZoneHolder.get().getId()),
            Arrays.asList(UaaAuthority.UAA_USER),
            null
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        MockHttpServletRequestBuilder post = post("/change_email.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("newEmail", "new@example.com")
            .param("client_id", "app");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile?error_message_code=email_change.non-uaa-origin"));

        Mockito.verifyZeroInteractions(changeEmailService);

    }

    @Test
    public void testInvalidEmail() throws Exception {
        setupSecurityContext();

        MockHttpServletRequestBuilder post = post("/change_email.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("newEmail", "invalid")
            .param("client_id", "app");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("change_email"))
            .andExpect(model().attribute("error_message_code", "invalid_email"))
            .andExpect(model().attribute("email", "user@example.com"));
    }

    @Test
    public void testVerifyEmail() throws Exception {
        UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
        UaaUser user = new UaaUser("user-id-001", "new@example.com", "password", "new@example.com", Collections.<GrantedAuthority>emptyList(), "name", "name", null, null, Origin.UAA, null, true, IdentityZoneHolder.get().getId(),"user-id-001");
        when(userDatabase.retrieveUserById(anyString())).thenReturn(user);

        controller.setUaaUserDatabase(userDatabase);
        assertSame(userDatabase, controller.getUaaUserDatabase());

        Map<String,String> response = new HashMap<>();
        response.put("userId", "user-id-001");
        response.put("username", "new@example.com");
        response.put("email", "new@example.com");
        when(changeEmailService.completeVerification("the_secret_code")).thenReturn(response);

        MockHttpServletRequestBuilder get = get("/verify_email")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "the_secret_code");

        mockMvc.perform(get)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile?success_message_code=email_change.success"));

        UaaPrincipal principal = ((UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        Assert.assertEquals("user-id-001", principal.getId());
        Assert.assertEquals("new@example.com", principal.getName());
        Assert.assertEquals("new@example.com", principal.getEmail());
    }

    @Test
    public void testVerifyEmailWithRedirectUrl() throws Exception {
        UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
        UaaUser user = new UaaUser("user-id-001", "new@example.com", "password", "new@example.com", Collections.<GrantedAuthority>emptyList(), "name", "name", null, null, Origin.UAA, null, true, IdentityZoneHolder.get().getId(),"user-id-001");
        when(userDatabase.retrieveUserById(anyString())).thenReturn(user);

        controller.setUaaUserDatabase(userDatabase);
        assertSame(userDatabase, controller.getUaaUserDatabase());

        Map<String,String> response = new HashMap<>();
        response.put("userId", "user-id-001");
        response.put("username", "new@example.com");
        response.put("email", "new@example.com");
        response.put("redirect_url", "//example.com/callback");
        when(changeEmailService.completeVerification("the_secret_code")).thenReturn(response);

        MockHttpServletRequestBuilder get = get("/verify_email")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "the_secret_code");

        mockMvc.perform(get)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("//example.com/callback"));

        UaaPrincipal principal = ((UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        Assert.assertEquals("user-id-001", principal.getId());
        Assert.assertEquals("new@example.com", principal.getName());
        Assert.assertEquals("new@example.com", principal.getEmail());

    }

    @Test
    public void testVerifyEmailWithInvalidCode() throws Exception {
        Authentication authentication = new AnonymousAuthenticationToken(
            "anon",
            "anonymousUser",
            AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        when(changeEmailService.completeVerification("the_secret_code")).thenThrow(new UaaException("Bad Request", 400));
        MockHttpServletRequestBuilder get = get("/verify_email")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "the_secret_code");

        mockMvc.perform(get)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("error"));

        setupSecurityContext();

        mockMvc.perform(get)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("profile?error_message_code=email_change.invalid_code"));
    }

    private void setupSecurityContext() {
        Authentication authentication = new UaaAuthentication(
            new UaaPrincipal("user-id-001", "bob", "user@example.com", Origin.UAA, null,IdentityZoneHolder.get().getId()),
            Arrays.asList(UaaAuthority.UAA_USER),
            null
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}