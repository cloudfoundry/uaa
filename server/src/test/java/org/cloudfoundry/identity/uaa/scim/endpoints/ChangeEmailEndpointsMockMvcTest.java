package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class ChangeEmailEndpointsMockMvcTest {

    @Mock
    private ScimUserProvisioning mockScimUserProvisioning;

    @Mock
    private ExpiringCodeStore mockExpiringCodeStore;

    @Mock
    private ApplicationEventPublisher mockApplicationEventPublisher;

    @Mock
    private QueryableResourceManager<ClientDetails> mockQueryableResourceManager;

    @Mock
    private IdentityZoneManager mockIdentityZoneManager;

    @InjectMocks
    private ChangeEmailEndpoints changeEmailEndpoints;

    private MockMvc mockMvc;
    private String currentIdentityZoneId;

    @BeforeEach
    void setUp() {
        currentIdentityZoneId = "currentIdentityZoneId-" + new AlphanumericRandomValueStringGenerator().generate();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        changeEmailEndpoints.setApplicationEventPublisher(mockApplicationEventPublisher);
        mockMvc = MockMvcBuilders.standaloneSetup(changeEmailEndpoints).build();
    }

    @Test
    void generateEmailChangeCode() throws Exception {
        String data = "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}";
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), eq(currentIdentityZoneId)))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + 1000), data, EMAIL.name()));

        ScimUser userChangingEmail = new ScimUser("user-id-001", "user@example.com", null, null);
        userChangingEmail.setOrigin("test");
        userChangingEmail.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("user-id-001", currentIdentityZoneId)).thenReturn(userChangingEmail);

        MockHttpServletRequestBuilder post = post("/email_verifications")
                .contentType(APPLICATION_JSON)
                .content(data)
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(content().string("secret_code"));
    }

    @Test
    void generateEmailChangeCodeWithExistingUsernameChange() throws Exception {
        String data = "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}";

        ScimUser userChangingEmail = new ScimUser("id001", "user@example.com", null, null);
        userChangingEmail.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("user-id-001", currentIdentityZoneId)).thenReturn(userChangingEmail);

        ScimUser existingUser = new ScimUser("id001", "new@example.com", null, null);
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("new@example.com"),
                eq(OriginKeys.UAA),
                eq(currentIdentityZoneId))
        ).thenReturn(Collections.singletonList(existingUser));

        MockHttpServletRequestBuilder post = post("/email_verifications")
                .contentType(APPLICATION_JSON)
                .content(data)
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isConflict());
    }

    @Test
    void changeEmail() throws Exception {
        when(mockExpiringCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId))
                .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\", \"client_id\":\"app\"}", EMAIL.name()));

        UaaClientDetails clientDetails = new UaaClientDetails();
        Map<String, String> additionalInformation = new HashMap<>();
        additionalInformation.put("change_email_redirect_url", "app_callback_url");
        clientDetails.setAdditionalInformation(additionalInformation);

        when(mockQueryableResourceManager.retrieve("app", currentIdentityZoneId))
                .thenReturn(clientDetails);

        ScimUser scimUser = new ScimUser();
        scimUser.setId("user-id-001");
        scimUser.setUserName("user@example.com");
        scimUser.setPrimaryEmail("user@example.com");

        when(mockScimUserProvisioning.retrieve("user-id-001", currentIdentityZoneId)).thenReturn(scimUser);

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
        verify(mockScimUserProvisioning).update(eq("user-id-001"), user.capture(), eq(currentIdentityZoneId));
        assertThat(user.getValue().getPrimaryEmail()).isEqualTo("new@example.com");
        assertThat(user.getValue().getUserName()).isEqualTo("new@example.com");

        ArgumentCaptor<UserModifiedEvent> event = ArgumentCaptor.forClass(UserModifiedEvent.class);
        verify(mockApplicationEventPublisher).publishEvent(event.capture());
        UserModifiedEvent userModifiedEvent = event.getValue();
        assertThat(userModifiedEvent.getUserId()).isEqualTo("user-id-001");
        assertThat(userModifiedEvent.getUsername()).isEqualTo("new@example.com");
        assertThat(userModifiedEvent.getEmail()).isEqualTo("new@example.com");
        assertThat(userModifiedEvent.getIdentityZoneId()).isEqualTo(currentIdentityZoneId);
    }

    @Test
    void changeEmailWhenUsernameNotTheSame() throws Exception {
        when(mockExpiringCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId))
                .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}", EMAIL.name()));

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName("username");
        scimUser.setPrimaryEmail("user@example.com");

        when(mockScimUserProvisioning.retrieve("user-id-001", currentIdentityZoneId)).thenReturn(scimUser);

        mockMvc.perform(post("/email_changes")
                        .contentType(APPLICATION_JSON)
                        .content("the_secret_code")
                        .accept(APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isOk());

        ArgumentCaptor<ScimUser> user = ArgumentCaptor.forClass(ScimUser.class);
        verify(mockScimUserProvisioning).update(eq("user-id-001"), user.capture(), eq(currentIdentityZoneId));

        assertThat(user.getValue().getPrimaryEmail()).isEqualTo("new@example.com");
        assertThat(user.getValue().getUserName()).isEqualTo("username");
    }

    @Test
    void changeEmail_withIncorrectCode() throws Exception {
        when(mockExpiringCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId))
                .thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), "{\"userId\":\"user-id-001\",\"email\":\"new@example.com\",\"client_id\":null}", "incorrect-code"));

        mockMvc.perform(post("/email_changes")
                        .contentType(APPLICATION_JSON)
                        .content("the_secret_code")
                        .accept(APPLICATION_JSON))
                .andExpect(MockMvcResultMatchers.status().isUnprocessableEntity());
    }
}
