package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.cloudfoundry.identity.uaa.authentication.Origin.UAA;
import static org.cloudfoundry.identity.uaa.login.EmailInvitationsService.EMAIL;
import static org.cloudfoundry.identity.uaa.login.EmailInvitationsService.USER_ID;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = EmailInvitationsServiceTests.ContextConfiguration.class)
@DirtiesContext(classMode=ClassMode.AFTER_EACH_TEST_METHOD)
public class EmailInvitationsServiceTests {

    @Autowired
    ConfigurableWebApplicationContext webApplicationContext;

    @Autowired
    ExpiringCodeStore expiringCodeStore;

    @Autowired
    EmailInvitationsService emailInvitationsService;

    @Autowired
    MessageService messageService;

    @Autowired
    ScimUserProvisioning scimUserProvisioning;

    @Autowired
    ClientDetailsService clientDetailsService;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testSendInviteEmail() throws Exception {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass((Class)String.class);

        ScimUser user = new ScimUser("existing-user-id", "marissa", "Marissa", "Koala");
        user.setPrimaryEmail("user@example.com");

        when(expiringCodeStore.generateCode(captor.capture(), anyObject())).thenReturn(new ExpiringCode("the_secret_code", null, null));
        emailInvitationsService.inviteUser(user, "current-user", "client-id", "blah.example.com");

        Map<String,String> data = JsonUtils.readValue(captor.getValue(), new TypeReference<Map<String,String>>() {});
        assertEquals("existing-user-id", data.get("user_id"));
        assertEquals("client-id", data.get("client_id"));
        assertEquals("blah.example.com", data.get("redirect_uri"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("user@example.com"),
            eq(MessageType.INVITATION),
            eq("Invitation to join Pivotal"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("current-user"));
        assertThat(emailBody, containsString("Pivotal"));
        assertThat(emailBody, containsString("<a href=\"http://localhost/invitations/accept?code=the_secret_code\">Accept Invite</a>"));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    @Test
    public void inviteUserWithoutClientIdOrRedirectUri() throws Exception {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass((Class)String.class);

        ScimUser user = new ScimUser("existing-user-id", "marissa", "Marissa", "Koala");
        user.setPrimaryEmail("user@example.com");

        when(expiringCodeStore.generateCode(captor.capture(), anyObject())).thenReturn(new ExpiringCode("the_secret_code", null, null));
        emailInvitationsService.inviteUser(user, "current-user", "", "");

        Map<String,String> data = JsonUtils.readValue(captor.getValue(), new TypeReference<Map<String, String>>() {});
        assertEquals("existing-user-id", data.get("user_id"));
        assertEquals("", data.get("client_id"));
        assertEquals("", data.get("redirect_uri"));
    }

    @Test
    public void testSendInviteEmailToUserThatIsAlreadyVerified() throws Exception {
        ScimUser user = new ScimUser("12345", "marissa", "Marissa", "Koala");
        user.setPrimaryEmail("user@example.com");
        user.setVerified(true);
        final ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        when(expiringCodeStore.generateCode(argumentCaptor.capture(), anyObject()))
            .thenAnswer(invocation -> new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), argumentCaptor.getValue()));

        emailInvitationsService.inviteUser(user, "current-user", "", "");
    }

    @Test
    public void testSendInviteEmailToUnverifiedUser() throws Exception {

        ScimUser user = new ScimUser("existing-user-id", "marissa", "Marissa", "Koala");
        user.setPrimaryEmail("existingunverified@example.com");
        user.setVerified(true);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass((Class)String.class);

        when(expiringCodeStore.generateCode(captor.capture(), anyObject())).thenReturn(new ExpiringCode("the_secret_code", null, null));
        emailInvitationsService.inviteUser(user, "current-user", "client-id", "blah.example.com");

        Map<String,String> data = JsonUtils.readValue(captor.getValue(), new TypeReference<Map<String, String>>() {});
        assertEquals("existing-user-id", data.get("user_id"));
        assertEquals("blah.example.com", data.get("redirect_uri"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("existingunverified@example.com"),
            eq(MessageType.INVITATION),
            eq("Invitation to join Pivotal"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("current-user"));
        assertThat(emailBody, containsString("Pivotal"));
        assertThat(emailBody, containsString("<a href=\"http://localhost/invitations/accept?code=the_secret_code\">Accept Invite</a>"));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    @Test
    public void testSendInviteEmailWithOSSBrand() throws Exception {
        emailInvitationsService.setBrand("oss");
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass((Class)String.class);

        ScimUser user = new ScimUser("existing-user-id", "marissa", "Marissa", "Koala");
        user.setPrimaryEmail("user@example.com");

        when(expiringCodeStore.generateCode(captor.capture(), anyObject())).thenReturn(new ExpiringCode("the_secret_code", null, null));
        emailInvitationsService.inviteUser(user, "current-user", "client-id", "blah.example.com");

        Map<String,String> data = JsonUtils.readValue(captor.getValue(), new TypeReference<Map<String, String>>() {});
        assertEquals("existing-user-id", data.get("user_id"));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
            eq("user@example.com"),
            eq(MessageType.INVITATION),
            eq("Invitation to join Cloud Foundry"),
            emailBodyArgument.capture()
        );
        String emailBody = emailBodyArgument.getValue();
        assertThat(emailBody, containsString("current-user"));
        assertThat(emailBody, containsString("<a href=\"http://localhost/invitations/accept?code=the_secret_code\">Accept Invite</a>"));
        assertThat(emailBody, containsString("Cloud Foundry"));
        assertThat(emailBody, not(containsString("Pivotal")));
    }

    @Test
    public void acceptInvitationNoClientId() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        when(scimUserProvisioning.retrieve(eq("user-id-001"))).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), anyObject())).thenReturn(user);

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        when(expiringCodeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData)));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();
        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion());
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password");
        assertEquals("/home", redirectLocation);
    }

    @Test
    public void acceptInvitationWithClientNotFound() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(Origin.UAA);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), anyObject())).thenReturn(user);
        when(scimUserProvisioning.retrieve(eq("user-id-001"))).thenReturn(user);
        doThrow(new NoSuchClientException("Client not found")).when(clientDetailsService).loadClientByClientId("client-not-found");

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "client-not-found");
        when(expiringCodeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData)));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion());
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password");
        assertEquals("/home", redirectLocation);
    }

    @Test
    public void acceptInvitationWithValidRedirectUri() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        BaseClientDetails clientDetails = new BaseClientDetails("client-id", null, null, null, null, "http://example.com/*/");
        when(scimUserProvisioning.retrieve(eq("user-id-001"))).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), anyObject())).thenReturn(user);
        when(clientDetailsService.loadClientByClientId("acmeClientId")).thenReturn(clientDetails);

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "acmeClientId");
        userData.put(REDIRECT_URI, "http://example.com/redirect/");
        when(expiringCodeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData)));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion());
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password");
        assertEquals("http://example.com/redirect/", redirectLocation);
    }

    @Test
    public void acceptInvitationWithInvalidRedirectUri() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        BaseClientDetails clientDetails = new BaseClientDetails("client-id", null, null, null, null, "http://example.com/redirect");
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), anyObject())).thenReturn(user);
        when(scimUserProvisioning.retrieve(eq("user-id-001"))).thenReturn(user);
        when(clientDetailsService.loadClientByClientId("acmeClientId")).thenReturn(clientDetails);
        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(REDIRECT_URI, "http://someother/redirect");
        userData.put(CLIENT_ID, "acmeClientId");
        when(expiringCodeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData)));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion());
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password");
        assertEquals("/home", redirectLocation);
    }

    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Autowired
        @Qualifier("mailTemplateEngine")
        SpringTemplateEngine templateEngine;

        @Bean
        ExpiringCodeStore expiringCodeService() { return mock(ExpiringCodeStore.class); }

        @Bean
        MessageService messageService() {
            return mock(MessageService.class);
        }

        @Bean
        EmailInvitationsService emailInvitationsService() {
            return new EmailInvitationsService(templateEngine, messageService(), "pivotal");
        }

        @Bean
        ClientDetailsService clientDetailsService() {
            return mock(ClientDetailsService.class);
        }

        @Bean
        ScimUserProvisioning scimUserProvisioning() {
            return mock(ScimUserProvisioning.class);
        }

    }
}
