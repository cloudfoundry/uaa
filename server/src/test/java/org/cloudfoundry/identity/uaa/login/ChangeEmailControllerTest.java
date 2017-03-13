package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.account.ChangeEmailController;
import org.cloudfoundry.identity.uaa.account.ChangeEmailService;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = ChangeEmailControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class ChangeEmailControllerTest extends TestClassNullifier {

    private MockMvc mockMvc;
    @Autowired
    private ChangeEmailService changeEmailService;
    @Autowired
    private UaaUserDatabase uaaUserDatabase;
    @Autowired
    WebApplicationContext webApplicationContext;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    public void testChangeEmailPage() throws Exception {
        setupSecurityContext();

        mockMvc.perform(get("/change_email").param("client_id", "client-id").param("redirect_uri", "http://example.com/redirect"))
            .andExpect(status().isOk())
            .andExpect(view().name("change_email"))
            .andExpect(model().attribute("email", "user@example.com"))
            .andExpect(model().attribute("client_id", "client-id"))
            .andExpect(model().attribute("redirect_uri", "http://example.com/redirect"))
            .andExpect(xpath("//*[@type='hidden' and @value='client-id']").exists())
            .andExpect(xpath("//*[@type='hidden' and @value='http://example.com/redirect']").exists());
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

        verify(changeEmailService).beginEmailChange("user-id-001", "bob", "new@example.com", "app", null);
    }

    @Test
    public void testChangeEmailWithClientIdAndRedirectUri() throws Exception {
        setupSecurityContext();

        MockHttpServletRequestBuilder post = post("/change_email.do")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("newEmail", "new@example.com")
                .param("client_id", "app")
                .param("redirect_uri", "http://redirect.uri");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("email_sent?code=email_change"));

        verify(changeEmailService).beginEmailChange("user-id-001", "bob", "new@example.com", "app", "http://redirect.uri");
    }

    @Test
    public void testChangeEmailWithUsernameConflict() throws Exception {
        setupSecurityContext();

        doThrow(new UaaException("username already exists", 409)).when(changeEmailService).beginEmailChange("user-id-001", "bob", "new@example.com", "", null);

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
        UaaUser user = new UaaUser("user-id-001", "new@example.com", "password", "new@example.com", Collections.<GrantedAuthority>emptyList(), "name", "name", null, null, OriginKeys.UAA, null, true, IdentityZoneHolder.get().getId(),"user-id-001", null);
        when(uaaUserDatabase.retrieveUserById(anyString())).thenReturn(user);

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
        UaaUser user = new UaaUser("user-id-001", "new@example.com", "password", "new@example.com", Collections.<GrantedAuthority>emptyList(), "name", "name", null, null, OriginKeys.UAA, null, true, IdentityZoneHolder.get().getId(),"user-id-001", null);
        when(uaaUserDatabase.retrieveUserById(anyString())).thenReturn(user);

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
            new UaaPrincipal("user-id-001", "bob", "user@example.com", OriginKeys.UAA, null,IdentityZoneHolder.get().getId()),
            Arrays.asList(UaaAuthority.UAA_USER),
            null
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new BuildInfo();
        }

        @Bean
        public ResourceBundleMessageSource messageSource() {
            ResourceBundleMessageSource resourceBundleMessageSource = new ResourceBundleMessageSource();
            resourceBundleMessageSource.setBasename("messages");
            return resourceBundleMessageSource;
        }

        @Bean
        ChangeEmailService changeEmailService() {
            return mock(ChangeEmailService.class);
        }

        @Bean
        UaaUserDatabase uaaUserDatabase() {
            return mock(UaaUserDatabase.class);
        }

        @Bean
        ChangeEmailController changeEmailController(ChangeEmailService changeEmailService) {
            ChangeEmailController changeEmailController = new ChangeEmailController(changeEmailService);
            changeEmailController.setUaaUserDatabase(uaaUserDatabase());
            return changeEmailController;
        }
    }
}
