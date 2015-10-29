package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.login.BuildInfo;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.collect.Lists.newArrayList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = InvitationsControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class InvitationsControllerTest {

    private MockMvc mockMvc;

    @Autowired
    ConfigurableWebApplicationContext webApplicationContext;

    @Autowired
    InvitationsService invitationsService;

    @Autowired
    ExpiringCodeStore expiringCodeStore;

    @Autowired
    PasswordValidator passwordValidator;

    @Autowired
    ClientDetailsService clientDetailsService;

    @Autowired
    IdentityProviderProvisioning providerProvisioning;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }


    @Test
    public void testAcceptInvitationsPage() throws Exception {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        when(expiringCodeStore.retrieveCode("the_secret_code")).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData)));
        when(expiringCodeStore.generateCode(anyString(), anyObject())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData)));
        IdentityProvider provider = new IdentityProvider();
        provider.setType(Origin.UAA);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(provider);
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                                            .param("code", "the_secret_code");

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(model().attribute("user_id", "user-id-001"))
            .andExpect(model().attribute("email", "user@example.com"))
            .andExpect(view().name("invitations/accept_invite"))
                .andExpect(xpath("//*[@type='hidden' and @value='client-id']").exists())
                .andExpect(xpath("//*[@type='hidden' and @value='blah.test.com']").exists());
        UaaPrincipal principal = ((UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        assertEquals("user-id-001", principal.getId());
        assertEquals("user@example.com", principal.getName());
        assertEquals("user@example.com", principal.getEmail());
    }

    @Test
    public void testAcceptInvitePageWithExpiredCode() throws Exception {
        when(expiringCodeStore.retrieveCode(anyString())).thenReturn(null);
        MockHttpServletRequestBuilder get = get("/invitations/accept").param("code", "the_secret_code");
        mockMvc.perform(get)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("invitations/accept_invite"))
            .andExpect(xpath("//*[@class='email-display']").doesNotExist())
            .andExpect(xpath("//form").doesNotExist());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testAcceptInviteWithContraveningPassword() throws Exception {
        doThrow(new InvalidPasswordException(newArrayList("Msg 2c", "Msg 1c"))).when(passwordValidator).validate("a");
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message", "Msg 1c Msg 2c"))
            .andExpect(view().name("invitations/accept_invite"));
        verify(invitationsService, never()).acceptInvitation(anyString(), anyString());
    }

    @Test
    public void testAcceptInvite() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com","fname", "lname");
        user.setPrimaryEmail(user.getUserName());
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("passw0rd");

        when(invitationsService.acceptInvitation(anyString(), eq("passw0rd"))).thenReturn(new InvitationsService.AcceptedInvitation("/home", user));

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));

        verify(invitationsService).acceptInvitation(anyString(), eq("passw0rd"));
    }

    public MockHttpServletRequestBuilder startAcceptInviteFlow(String password) {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null, IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        return post("/invitations/accept.do")
            .param("code","thecode")
            .param("password", password)
            .param("password_confirmation", password);
    }

    @Test
    public void acceptInviteWithValidClientRedirect() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null,IdentityZoneHolder.get().getId());
        ScimUser user = new ScimUser(uaaPrincipal.getId(), uaaPrincipal.getName(),"fname", "lname");
        user.setPrimaryEmail(user.getUserName());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        when(invitationsService.acceptInvitation(anyString(), eq("password"))).thenReturn(new InvitationsService.AcceptedInvitation("valid.redirect.com", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "valid-app")
            .param("redirect_uri", "valid.redirect.com")
            .param("code","thecode");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("valid.redirect.com"));
    }

    @Test
    public void acceptInviteWithInvalidClientRedirect() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null,IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        ScimUser user = new ScimUser(uaaPrincipal.getId(), uaaPrincipal.getName(),"fname", "lname");
        user.setPrimaryEmail(user.getUserName());

        when(invitationsService.acceptInvitation(anyString(), eq("password"))).thenReturn(new InvitationsService.AcceptedInvitation("/home", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("code","thecode")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "valid-app")
            .param("redirect_uri", "invalid.redirect.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));
    }

    @Test
    public void testAcceptInviteWithoutMatchingPasswords() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null,IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("code", "thecode")
            .param("password", "password")
            .param("password_confirmation", "does not match");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "form_error"))
            .andExpect(model().attribute("email", "user@example.com"))
            .andExpect(view().name("invitations/accept_invite"));

        verifyZeroInteractions(invitationsService);
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
        public UaaUserDatabase userDatabase() {
            UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
            UaaUser user = new UaaUser("user@example.com","","user@example.com","Given","family");
            user = user.modifyId("user-id-001");
            when (userDatabase.retrieveUserById(user.getId())).thenReturn(user);
            return userDatabase;
        }

        @Bean
        public ResourceBundleMessageSource messageSource() {
            ResourceBundleMessageSource resourceBundleMessageSource = new ResourceBundleMessageSource();
            resourceBundleMessageSource.setBasename("messages");
            return resourceBundleMessageSource;
        }

        @Bean
        InvitationsService invitationsService() {
            return mock(InvitationsService.class);
        }

        @Bean
        InvitationsController invitationsController(InvitationsService invitationsService,
                                                    ExpiringCodeStore codeStore,
                                                    PasswordValidator passwordPolicyValidator,
                                                    IdentityProviderProvisioning providerProvisioning,
                                                    UaaUserDatabase userDatabase) {
            InvitationsController result = new InvitationsController(invitationsService);
            result.setExpiringCodeStore(codeStore);
            result.setPasswordValidator(passwordPolicyValidator);
            result.setProviderProvisioning(providerProvisioning);
            result.setUserDatabase(userDatabase);
            return result;
        }

        @Bean
        ExpiringCodeStore expiringCodeStore() {
            return mock(ExpiringCodeStore.class);
        }

        @Bean
        PasswordValidator uaaPasswordValidator() { return mock(PasswordValidator.class); }

        @Bean
        IdentityProviderProvisioning providerProvisioning() {

            return mock (IdentityProviderProvisioning.class);
        }

        @Bean
        ClientDetailsService clientDetailsService() {
            return mock(ClientDetailsService.class);
        }

        @Bean
        DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager() {
            return mock(DynamicZoneAwareAuthenticationManager.class);
        }

    }
}
