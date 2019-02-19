package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ChangeEmailEndpointsTest extends TestClassNullifier {

    private ScimUserProvisioning scimUserProvisioning;
    private MockMvc mockMvc;
    private ExpiringCodeStore expiringCodeStore;
    private ApplicationEventPublisher publisher;
    private QueryableResourceManager<ClientDetails> clientDetailsService;


    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        expiringCodeStore = Mockito.mock(ExpiringCodeStore.class);
        publisher = Mockito.mock(ApplicationEventPublisher.class);
        clientDetailsService = Mockito.mock(QueryableResourceManager.class);
        ChangeEmailEndpoints changeEmailEndpoints = new ChangeEmailEndpoints(scimUserProvisioning, expiringCodeStore, clientDetailsService);
        changeEmailEndpoints.setApplicationEventPublisher(publisher);
        mockMvc = MockMvcBuilders.standaloneSetup(changeEmailEndpoints).build();
    }

    @Test
    public void testGenerateEmailChangeCode() throws Exception {
        String data = "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}";
        when(expiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), eq(IdentityZoneHolder.get().getId())))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + 1000), data, EMAIL.name()));

        ScimUser userChangingEmail = new ScimUser("user-id-001", "user@example.com", null, null);
        userChangingEmail.setOrigin("test");
        userChangingEmail.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-id-001", IdentityZoneHolder.get().getId())).thenReturn(userChangingEmail);

        MockHttpServletRequestBuilder post = post("/email_verifications")
            .contentType(APPLICATION_JSON)
            .content(data)
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isCreated())
            .andExpect(content().string("secret_code"));
    }

    @Test
    public void testGenerateEmailChangeCodeWithExistingUsernameChange() throws Exception {
        String data = "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}";

        ScimUser userChangingEmail = new ScimUser("id001", "user@example.com", null, null);
        userChangingEmail.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-id-001", IdentityZoneHolder.get().getId())).thenReturn(userChangingEmail);

        ScimUser existingUser = new ScimUser("id001", "new@example.com", null, null);
        when(scimUserProvisioning.query("userName eq \"new@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
            .thenReturn(Arrays.asList(existingUser));

        MockHttpServletRequestBuilder post = post("/email_verifications")
            .contentType(APPLICATION_JSON)
            .content(data)
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isConflict());
    }

    @Test
    public void testChangeEmail() throws Exception {
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId()))
            .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\", \"client_id\":\"app\"}", EMAIL.name()));

        BaseClientDetails clientDetails = new BaseClientDetails();
        Map<String, String> additionalInformation = new HashMap<>();
        additionalInformation.put(ChangeEmailEndpoints.CHANGE_EMAIL_REDIRECT_URL, "app_callback_url");
        clientDetails.setAdditionalInformation(additionalInformation);

        when(clientDetailsService.retrieve("app", IdentityZoneHolder.get().getId()))
            .thenReturn(clientDetails);

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName("user@example.com");
        scimUser.setPrimaryEmail("user@example.com");

        when(scimUserProvisioning.retrieve("user-id-001", IdentityZoneHolder.get().getId())).thenReturn(scimUser);

        mockMvc.perform(post("/email_changes")
            .contentType(APPLICATION_JSON)
            .content("the_secret_code")
            .accept(APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.jsonPath("$.userId").value("user-id-001"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.username").value("new@example.com"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("new@example.com"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.redirect_url").value("app_callback_url"))
            .andExpect(MockMvcResultMatchers.status().isOk());

        ArgumentCaptor<ScimUser> user = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(eq("user-id-001"), user.capture(), eq(IdentityZoneHolder.get().getId()));
        Assert.assertEquals("new@example.com", user.getValue().getPrimaryEmail());
        Assert.assertEquals("new@example.com", user.getValue().getUserName());

        ArgumentCaptor<UserModifiedEvent> event = ArgumentCaptor.forClass(UserModifiedEvent.class);
        verify(publisher).publishEvent(event.capture());
        Assert.assertEquals("user-id-001", event.getValue().getUserId());
        Assert.assertEquals("new@example.com", event.getValue().getUsername());
        Assert.assertEquals("new@example.com", event.getValue().getEmail());
    }

    @Test
    public void testChangeEmailWhenUsernameNotTheSame() throws Exception {
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId()))
            .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}", EMAIL.name()));

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName("username");
        scimUser.setPrimaryEmail("user@example.com");

        when(scimUserProvisioning.retrieve("user-id-001", IdentityZoneHolder.get().getId())).thenReturn(scimUser);

        mockMvc.perform(post("/email_changes")
            .contentType(APPLICATION_JSON)
            .content("the_secret_code")
            .accept(APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.status().isOk());

        ArgumentCaptor<ScimUser> user = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(eq("user-id-001"), user.capture(), eq(IdentityZoneHolder.get().getId()));

        Assert.assertEquals("new@example.com", user.getValue().getPrimaryEmail());
        Assert.assertEquals("username", user.getValue().getUserName());
    }

    @Test
    public void changeEmail_withIncorrectCode() throws Exception {
        when(expiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId()))
            .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}", "incorrect-code"));

        mockMvc.perform(post("/email_changes")
            .contentType(APPLICATION_JSON)
            .content("the_secret_code")
            .accept(APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.status().isUnprocessableEntity());
    }
}
