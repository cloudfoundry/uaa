package org.cloudfoundry.identity.uaa.login;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doThrow;
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

import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.ExpiringCodeService.CodeNotFoundException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
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

    @Before
    public void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }
    
    @After
    public void tearDown() {
    	SecurityContextHolder.clearContext();
    }

    @Test
    public void testNewInvitePage() throws Exception {
        MockHttpServletRequestBuilder get = get("/invitations/new");

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(view().name("invitations/new_invite"));
    }

    @Test
    public void testSendInvitationEmail() throws Exception {
        UaaPrincipal p = new UaaPrincipal("123","marissa","marissa@test.org", Origin.UAA,"");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        assertTrue(auth.isAuthenticated());
        MockSecurityContext mockSecurityContext = new MockSecurityContext(auth);
        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            mockSecurityContext
        );

        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .param("email", "user1@example.com");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("sent"));
        verify(invitationsService).inviteUser("user1@example.com", "marissa");
    }
    
    @Test
    public void testSendInvitationEmailToExistingVerifiedUser() throws Exception {
        UaaPrincipal p = new UaaPrincipal("123","marissa","marissa@test.org", Origin.UAA,"");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        assertTrue(auth.isAuthenticated());
        MockSecurityContext mockSecurityContext = new MockSecurityContext(auth);
        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            mockSecurityContext
        );

        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .param("email", "user1@example.com");

        doThrow(new UaaException("",409)).when(invitationsService).inviteUser("user1@example.com", "marissa");
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("invitations/new_invite"))
            .andExpect(model().attribute("error_message_code", "existing_user"));
    }

    @Test
    public void testSendInvitationWithInvalidEmail() throws Exception {
        UaaPrincipal p = new UaaPrincipal("123","marissa","marissa@test.org", Origin.UAA,"");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(p, "", UaaAuthority.USER_AUTHORITIES);
        assertTrue(auth.isAuthenticated());
        MockSecurityContext mockSecurityContext = new MockSecurityContext(auth);
        SecurityContextHolder.setContext(mockSecurityContext);
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            mockSecurityContext
        );

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
    	when(expiringCodeService.verifyCode("the_secret_code")).thenReturn(codeData);
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                                            .param("code", "the_secret_code");

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(model().attribute("user_id", "user-id-001"))
            .andExpect(model().attribute("email", "user@example.com"))
            .andExpect(view().name("invitations/accept_invite"));
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
    public void testAcceptInvite() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);
        
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"));
        
        verify(invitationsService).acceptInvitation("user-id-001","user@example.com", "password", "");
    }

    @Test
    public void testAcceptInviteWithClientRedirect() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        when(invitationsService.acceptInvitation("user-id-001", "user@example.com", "password", "app")).thenReturn("http://localhost:8080/app");

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "app");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost:8080/app"));
    }

    @Test
    public void testAcceptInviteWithoutMatchingPasswords() throws Exception {
    	UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", Origin.UAA, null);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);
        
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
            .param("password", "password")
            .param("password_confirmation", "does not match")
            .param("client_id", "");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "form_error"))
            .andExpect(model().attribute("email", "user@example.com"))
            .andExpect(view().name("invitations/accept_invite"));

        verifyZeroInteractions(invitationsService);
    }


    public static class MockSecurityContext implements SecurityContext {

        private static final long serialVersionUID = -1386535243513362694L;

        private Authentication authentication;

        public MockSecurityContext(Authentication authentication) {
            this.authentication = authentication;
        }

        @Override
        public Authentication getAuthentication() {
            return this.authentication;
        }

        @Override
        public void setAuthentication(Authentication authentication) {
            this.authentication = authentication;
        }
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
            return Mockito.mock(InvitationsService.class);
        }

        @Bean
        InvitationsController invitationsController(InvitationsService invitationsService) {
            return new InvitationsController(invitationsService);
        }
        
        @Bean 
        ExpiringCodeService expiringCodeService() {
        	return Mockito.mock(ExpiringCodeService.class);
        }
    }
}
