package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.ExpiringCodeService.CodeNotFoundException;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
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
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
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
    ExpiringCodeService expiringCodeService;

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
    public void test_IDP_Domain_Filter() throws Exception {
        InvitationsController controller = webApplicationContext.getBean(InvitationsController.class);
        IdentityProvider provider = mock(IdentityProvider.class);
        UaaIdentityProviderDefinition definition = mock(UaaIdentityProviderDefinition.class);
        when(provider.getType()).thenReturn(Origin.UAA);
        when(provider.getConfigValue(UaaIdentityProviderDefinition.class)).thenReturn(definition);
        when(provider.getConfig()).thenReturn("");
        when(definition.getEmailDomain()).thenReturn(null);
        assertTrue(controller.doesEmailDomainMatchProvider(provider, "test.com"));
        when(definition.getEmailDomain()).thenReturn(Collections.EMPTY_LIST);
        assertFalse(controller.doesEmailDomainMatchProvider(provider, "test.com"));
        when(definition.getEmailDomain()).thenReturn(Arrays.asList("test.org","test.com"));
        assertTrue(controller.doesEmailDomainMatchProvider(provider, "test.com"));
    }

    @Test
    public void test_doesEmailDomainMatchProvider() throws Exception {
        IdentityProvider uaaProvider = new IdentityProvider();
        uaaProvider.setType(Origin.UAA).setOriginKey(Origin.UAA).setId(Origin.UAA);

        IdentityProvider ldapProvider = new IdentityProvider();
        ldapProvider.setType(Origin.LDAP).setOriginKey(Origin.LDAP).setId(Origin.LDAP);

        IdentityProvider samlProvider = new IdentityProvider();
        samlProvider.setType(Origin.SAML).setOriginKey(Origin.SAML).setId(Origin.SAML);

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = new SamlIdentityProviderDefinition("http://some.meta.data", Origin.SAML, "nameID", 0, true, true, "Saml Link Text", null, IdentityZoneHolder.get().getId());
        LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes("baseUrl","bindUserDN","bindUserPassword","userSearchBase","userSearchFilter","groupSearchBase","groupSearchFilter","mail", null, false, false, false,1,true);
        UaaIdentityProviderDefinition  uaaIdentityProviderDefinition  = new UaaIdentityProviderDefinition();

        when(providerProvisioning.retrieveActive(anyString())).thenReturn(Arrays.asList(uaaProvider, ldapProvider, samlProvider));

        InvitationsController controller = webApplicationContext.getBean(InvitationsController.class);
        assertThat(controller.filterIdpsForClientAndEmailDomain(null, "test@test.org"), containsInAnyOrder(uaaProvider, ldapProvider, samlProvider));

        uaaProvider.setConfig(JsonUtils.writeValueAsString(uaaIdentityProviderDefinition));
        ldapProvider.setConfig(JsonUtils.writeValueAsString(ldapIdentityProviderDefinition));
        samlProvider.setConfig(JsonUtils.writeValueAsString(samlIdentityProviderDefinition));
        assertThat(controller.filterIdpsForClientAndEmailDomain(null, "test@test.org"), containsInAnyOrder(uaaProvider, ldapProvider, samlProvider));

        uaaProvider.setConfig(JsonUtils.writeValueAsString(uaaIdentityProviderDefinition.setEmailDomain(Arrays.asList("test1.org", "test2.org"))));
        assertThat(controller.filterIdpsForClientAndEmailDomain(null, "test@test.org"), containsInAnyOrder(ldapProvider, samlProvider));

        ldapProvider.setConfig(JsonUtils.writeValueAsString(ldapIdentityProviderDefinition.setEmailDomain(Arrays.asList("test1.org", "test2.org"))));
        assertThat(controller.filterIdpsForClientAndEmailDomain(null, "test@test.org"), containsInAnyOrder(samlProvider));


        samlProvider.setConfig(JsonUtils.writeValueAsString(samlIdentityProviderDefinition.setEmailDomain(Arrays.asList("test1.org", "test2.org"))));
        assertThat(controller.filterIdpsForClientAndEmailDomain(null, "test@test.org"), empty());

        uaaProvider.setConfig(JsonUtils.writeValueAsString(uaaIdentityProviderDefinition.setEmailDomain(Collections.EMPTY_LIST)));
        ldapProvider.setConfig(JsonUtils.writeValueAsString(ldapIdentityProviderDefinition.setEmailDomain(Collections.EMPTY_LIST)));
        samlProvider.setConfig(JsonUtils.writeValueAsString(samlIdentityProviderDefinition.setEmailDomain(Collections.EMPTY_LIST)));
        assertThat(controller.filterIdpsForClientAndEmailDomain(null, "test@test.org"), containsInAnyOrder());

        uaaProvider.setConfig(JsonUtils.writeValueAsString(uaaIdentityProviderDefinition.setEmailDomain(null)));
        ldapProvider.setConfig(JsonUtils.writeValueAsString(ldapIdentityProviderDefinition.setEmailDomain(null)));
        samlProvider.setConfig(JsonUtils.writeValueAsString(samlIdentityProviderDefinition.setEmailDomain(null)));
        String clientId = "client_id";
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials","");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Arrays.asList(Origin.UAA, Origin.SAML));
        when(clientDetailsService.loadClientByClientId(eq(clientId))).thenReturn(client);
        assertThat(controller.filterIdpsForClientAndEmailDomain(clientId, "test@test.org"), containsInAnyOrder(uaaProvider, samlProvider));

        uaaProvider.setConfig(JsonUtils.writeValueAsString(uaaIdentityProviderDefinition.setEmailDomain(Arrays.asList("test1.org", "test2.org"))));
        assertThat(controller.filterIdpsForClientAndEmailDomain(clientId, "test@test.org"), containsInAnyOrder(samlProvider));

    }

    @Test
    public void testNewInvitePage() throws Exception {
        MockHttpServletRequestBuilder get = get("/invitations/new");

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(view().name("invitations/new_invite"));
    }

    @Test
    public void newInvitePageWithClientIdAndRedirectUri() throws Exception {
        MockHttpServletRequestBuilder get = get("/invitations/new?client_id=client-id&redirect_uri=blah.example.com");

        mockMvc.perform(get)
            .andExpect(model().attribute("redirect_uri", "blah.example.com"))
            .andExpect(model().attribute("client_id", "client-id"))
            .andExpect(status().isOk())
            .andExpect(view().name("invitations/new_invite"))
            .andExpect(xpath("//*[@type='hidden' and @value='blah.example.com']").exists())
            .andExpect(xpath("//*[@type='hidden' and @value='client-id']").exists());
    }

    @Test
    public void testSendInvitationEmail() throws Exception {
        UsernamePasswordAuthenticationToken auth = getMarissaAuthentication();
        SecurityContextHolder.getContext().setAuthentication(auth);

        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .param("email", "user1@example.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("sent"));
        verify(invitationsService).inviteUser("user1@example.com", "marissa", "", "");
    }

    @Test
    public void sendInvitationWithValidClientIdAndRedirectUri() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(getMarissaAuthentication());
        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .param("email", "user1@example.com")
            .param("client_id", "client-id")
            .param("redirect_uri", "blah.example.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("sent"));
        verify(invitationsService).inviteUser("user1@example.com", "marissa", "client-id", "blah.example.com");
    }

    protected UsernamePasswordAuthenticationToken getMarissaAuthentication() {
        UaaPrincipal p = new UaaPrincipal("123","marissa","marissa@test.org", Origin.UAA,"", IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        assertTrue(auth.isAuthenticated());
        return auth;
    }

    @Test
    public void newInvitePageWithRedirectUri() throws Exception {
        MockHttpServletRequestBuilder get = get("/invitations/new?redirect_uri=blah.example.com");

        mockMvc.perform(get)
            .andExpect(model().attribute("redirect_uri", "blah.example.com"))
            .andExpect(status().isOk())
            .andExpect(view().name("invitations/new_invite"))
            .andExpect(xpath("//*[@type='hidden' and @value='blah.example.com']").exists());
    }


    @Test
    public void testSendInvitationEmailToExistingVerifiedUser() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(getMarissaAuthentication());

        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .param("email", "user1@example.com");

        doThrow(new UaaException("",409)).when(invitationsService).inviteUser("user1@example.com", "marissa", "", "");
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("invitations/new_invite"))
            .andExpect(model().attribute("error_message_code", "existing_user"));
    }

    @Test
    public void testSendInvitationWithInvalidEmail() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(getMarissaAuthentication());

        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .param("email", "not_a_real_email");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "invalid_email"))
            .andExpect(view().name("invitations/new_invite"));

        verifyZeroInteractions(invitationsService);
    }

    @Test
    public void testAcceptInvitationsPage() throws Exception {
        Map<String,String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        when(expiringCodeService.verifyCode("the_secret_code")).thenReturn(codeData);

        IdentityProvider uaaProvider = new IdentityProvider();
        uaaProvider.setType(Origin.UAA).setOriginKey(Origin.UAA).setId(Origin.UAA);
        when(providerProvisioning.retrieveActive(anyString())).thenReturn(Arrays.asList(uaaProvider));

        when(clientDetailsService.loadClientByClientId(anyString())).thenThrow(new NoSuchClientException("mock"));

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
    	doThrow(new CodeNotFoundException("code expired")).when(expiringCodeService).verifyCode("the_secret_code");
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
        verify(invitationsService, never()).acceptInvitation(anyString(), anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    public void testAcceptInvite() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com","fname", "lname");
        user.setPrimaryEmail(user.getUserName());
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("passw0rd");

        when(invitationsService.acceptInvitation("user-id-001","user@example.com", "passw0rd", "", "", Origin.UAA)).thenReturn(new InvitationsService.AcceptedInvitation("/home",user));

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));

        verify(invitationsService).acceptInvitation("user-id-001","user@example.com", "passw0rd", "", "", Origin.UAA);
    }

    public MockHttpServletRequestBuilder startAcceptInviteFlow(String password) {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null, IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        return post("/invitations/accept.do")
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

        when(invitationsService.acceptInvitation("user-id-001", "user@example.com", "password", "valid-app", "valid.redirect.com", Origin.UAA)).thenReturn(new InvitationsService.AcceptedInvitation("valid.redirect.com", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "valid-app")
            .param("redirect_uri", "valid.redirect.com");

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

        when(invitationsService.acceptInvitation("user-id-001", "user@example.com", "password", "valid-app", "invalid.redirect.com", Origin.UAA)).thenReturn(new InvitationsService.AcceptedInvitation("/home", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
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
        InvitationsController invitationsController(InvitationsService invitationsService) {
            return new InvitationsController(invitationsService);
        }

        @Bean
        ExpiringCodeService expiringCodeService() {
            return mock(ExpiringCodeService.class);
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
