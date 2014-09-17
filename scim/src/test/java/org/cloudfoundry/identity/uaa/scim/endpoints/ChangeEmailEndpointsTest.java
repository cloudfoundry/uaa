package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class ChangeEmailEndpointsTest {

    private ScimUserProvisioning scimUserProvisioning;
    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        ChangeEmailEndpoints changeEmailEndpoints = new ChangeEmailEndpoints(scimUserProvisioning);
        mockMvc = MockMvcBuilders.standaloneSetup(changeEmailEndpoints).build();
    }

    @Test
    public void testChangeEmail() throws Exception {
        ScimUser scimUser = new ScimUser();

        when(scimUserProvisioning.retrieve("user-id-001")).thenReturn(scimUser);

        mockMvc.perform(post("/email_changes")
            .contentType(APPLICATION_JSON)
            .param("userId", "user-id-001")
            .param("newEmail", "new@example.com")
            .content("{\"userId\":\"user-id-001\",\"newEmail\":\"new@example.com\"}")
            .accept(APPLICATION_JSON))
            .andExpect(MockMvcResultMatchers.status().isOk());

        ArgumentCaptor<ScimUser> user = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(eq("user-id-001"), user.capture());

        Assert.assertEquals("new@example.com", user.getValue().getPrimaryEmail());

    }
}