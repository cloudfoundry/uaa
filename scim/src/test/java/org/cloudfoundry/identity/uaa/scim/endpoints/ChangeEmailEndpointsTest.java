package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.audit.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;

import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class ChangeEmailEndpointsTest {

    private ScimUserProvisioning scimUserProvisioning;
    private MockMvc mockMvc;
    private ExpiringCodeStore expiringCodeStore;
    private ApplicationEventPublisher publisher;

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        expiringCodeStore = Mockito.mock(ExpiringCodeStore.class);
        publisher = Mockito.mock(ApplicationEventPublisher.class);
        ChangeEmailEndpoints changeEmailEndpoints = new ChangeEmailEndpoints(scimUserProvisioning, expiringCodeStore, new ObjectMapper());
        changeEmailEndpoints.setApplicationEventPublisher(publisher);
        mockMvc = MockMvcBuilders.standaloneSetup(changeEmailEndpoints).build();
    }

    @Test
    public void testChangeEmail() throws Exception {
        Mockito.when(expiringCodeStore.retrieveCode("the_secret_code"))
            .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\"}"));

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName("user@example.com");
        scimUser.setPrimaryEmail("user@example.com");

        when(scimUserProvisioning.retrieve("user-id-001")).thenReturn(scimUser);

        mockMvc.perform(post("/email_changes")
            .contentType(APPLICATION_JSON)
            .content("the_secret_code")
            .accept(APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.jsonPath("$.userId").value("user-id-001"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.username").value("new@example.com"))
            .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("new@example.com"))
            .andExpect(MockMvcResultMatchers.status().isOk());

        ArgumentCaptor<ScimUser> user = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(eq("user-id-001"), user.capture());
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
        Mockito.when(expiringCodeStore.retrieveCode("the_secret_code"))
            .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\"}"));

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName("username");
        scimUser.setPrimaryEmail("user@example.com");

        when(scimUserProvisioning.retrieve("user-id-001")).thenReturn(scimUser);

        mockMvc.perform(post("/email_changes")
            .contentType(APPLICATION_JSON)
            .content("the_secret_code")
            .accept(APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.status().isOk());

        ArgumentCaptor<ScimUser> user = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(eq("user-id-001"), user.capture());

        Assert.assertEquals("new@example.com", user.getValue().getPrimaryEmail());
        Assert.assertEquals("username", user.getValue().getUserName());
    }
}