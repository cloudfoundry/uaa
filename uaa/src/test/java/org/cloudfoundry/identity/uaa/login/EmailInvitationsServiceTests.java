package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.invitations.EmailInvitationsService;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.invitations.EmailInvitationsService.EMAIL;
import static org.cloudfoundry.identity.uaa.invitations.EmailInvitationsService.USER_ID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
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
    MultitenantClientServices clientDetailsService;


    @BeforeEach
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @AfterEach
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void acceptInvitationNoClientId() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), any(), eq(zoneId))).thenReturn(user);

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();
        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertEquals("/home", redirectLocation);
    }

    @Test
    public void nonMatchingCodeIntent() {
        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        when(expiringCodeStore.retrieveCode(anyString(), eq(IdentityZoneHolder.get().getId()))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), "wrong-intent"));

        HttpClientErrorException httpClientErrorException = Assertions.assertThrows(HttpClientErrorException.class,
                () -> emailInvitationsService.acceptInvitation("code", "password").getRedirectUri());

        assertThat(httpClientErrorException.getMessage(), CoreMatchers.containsString("400 BAD_REQUEST"));
    }

    @Test
    public void acceptInvitation_withoutPasswordUpdate() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        emailInvitationsService.acceptInvitation("code", "").getRedirectUri();
        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(scimUserProvisioning, never()).changePassword(anyString(), anyString(), anyString(), eq(zoneId));
    }

    @Test
    public void acceptInvitation_onlyMarksInternalUsersAsVerified() {
        ScimUser user = new ScimUser("ldap-user-id", "ldapuser", "Charlie", "Brown");
        user.setOrigin(LDAP);

        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(eq("ldap-user-id"), eq(zoneId))).thenReturn(user);

        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "ldap-user-id");
        userData.put(EMAIL, "ldapuser");
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        emailInvitationsService.acceptInvitation("code", "").getRedirectUri();

        verify(scimUserProvisioning, never()).verifyUser(anyString(), anyInt(), anyString());
    }

    @Test
    public void acceptInvitationWithClientNotFound() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(OriginKeys.UAA);
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), any(), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        doThrow(new NoSuchClientException("Client not found")).when(clientDetailsService).loadClientByClientId("client-not-found");

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "client-not-found");
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertEquals("/home", redirectLocation);
    }

    @Test
    public void acceptInvitationWithValidRedirectUri() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        BaseClientDetails clientDetails = new BaseClientDetails("client-id", null, null, null, null, "http://example.com/*/");
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), any(), eq(zoneId))).thenReturn(user);
        when(clientDetailsService.loadClientByClientId("acmeClientId", "uaa")).thenReturn(clientDetails);

        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "acmeClientId");
        userData.put(REDIRECT_URI, "http://example.com/redirect/");
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertEquals("http://example.com/redirect/", redirectLocation);
    }

    @Test
    public void acceptInvitationWithInvalidRedirectUri() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        BaseClientDetails clientDetails = new BaseClientDetails("client-id", null, null, null, null, "http://example.com/redirect");
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.update(anyString(), any(), eq(zoneId))).thenReturn(user);
        when(scimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(clientDetailsService.loadClientByClientId("acmeClientId")).thenReturn(clientDetails);
        Map<String,String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(REDIRECT_URI, "http://someother/redirect");
        userData.put(CLIENT_ID, "acmeClientId");
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(scimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(scimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
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

        @Bean
        ExpiringCodeStore expiringCodeService() { return mock(ExpiringCodeStore.class); }

        @Bean
        MessageService messageService() {
            return mock(MessageService.class);
        }

        @Bean
        EmailInvitationsService emailInvitationsService() {
            return new EmailInvitationsService();
        }

        @Bean
        MultitenantClientServices clientDetailsService() {
            return mock(MultitenantClientServices.class);
        }

        @Bean
        ScimUserProvisioning scimUserProvisioning() {
            return mock(ScimUserProvisioning.class);
        }

    }
}
