package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.assertj.core.groups.Tuple;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_PLAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class ClientMetadataAdminEndpointsMockMvcTest {

    @Autowired
    public WebApplicationContext webApplicationContext;
    private String adminClientTokenWithClientsWrite;
    private MultitenantJdbcClientDetailsService clients;
    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator(8);
    private String adminClientTokenWithClientsRead;
    @Autowired
    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeEach
    void setUp() throws Exception {
        testClient = new TestClient(mockMvc);

        UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);
        adminClientTokenWithClientsRead = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.read");
        adminClientTokenWithClientsWrite = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.write");

        clients = webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class);
    }

    @Test
    void getClientMetadata() throws Exception {
        String clientId = generator.generate();

        String marissaToken = getUserAccessToken(clientId);
        MockHttpServletResponse response = getTestClientMetadata(clientId, marissaToken);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    private String getUserAccessToken(String clientId) throws Exception {
        UaaClientDetails newClient = new UaaClientDetails(clientId,
                "oauth",
                "oauth.approvals",
                "password",
                "oauth.login");
        newClient.setClientSecret("secret");
        clients.addClientDetails(newClient);
        return testClient.getUserOAuthAccessToken(clientId, "secret", "marissa", "koala", "oauth.approvals");
    }

    @Test
    void getClientMetadata_WhichDoesNotExist() throws Exception {
        String clientId = generator.generate();
        MockHttpServletResponse response = getTestClientMetadata(clientId, adminClientTokenWithClientsRead);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.NOT_FOUND.value());
    }

    @Test
    void getAllClientMetadata() throws Exception {
        String clientId1 = generator.generate();
        String marissaToken = getUserAccessToken(clientId1);

        String clientId2 = generator.generate();
        clients.addClientDetails(new UaaClientDetails(clientId2, null, null, null, null));

        String clientId3 = generator.generate();
        clients.addClientDetails(new UaaClientDetails(clientId3, null, null, null, null));
        ClientMetadata client3Metadata = new ClientMetadata();
        client3Metadata.setClientId(clientId3);
        client3Metadata.setIdentityZoneId("uaa");
        client3Metadata.setAppLaunchUrl(URI.create("http://client3.com/app").toURL());
        client3Metadata.setShowOnHomePage(true);
        client3Metadata.setAppIcon("Y2xpZW50IDMgaWNvbg==");
        performUpdate(client3Metadata);

        String clientId4 = generator.generate();
        clients.addClientDetails(new UaaClientDetails(clientId4, null, null, null, null));
        ClientMetadata client4Metadata = new ClientMetadata();
        client4Metadata.setClientId(clientId4);
        client4Metadata.setIdentityZoneId("uaa");
        client4Metadata.setAppLaunchUrl(URI.create("http://client4.com/app").toURL());
        client4Metadata.setAppIcon("aWNvbiBmb3IgY2xpZW50IDQ=");
        performUpdate(client4Metadata);

        MockHttpServletResponse response = mockMvc.perform(get("/oauth/clients/meta")
                .header("Authorization", "Bearer " + marissaToken)
                .accept(APPLICATION_JSON)).andExpect(status().isOk()).andReturn().getResponse();
        ArrayList<ClientMetadata> clientMetadataList = JsonUtils.readValue(response.getContentAsString(),
                new TypeReference<>() {
                });

        assertThat(clientMetadataList).extracting(ClientMetadata::getClientId).doesNotContain(clientId1);
        assertThat(clientMetadataList).extracting(ClientMetadata::getClientId)
                .doesNotContain(clientId1)
                .doesNotContain(clientId2);
        assertThat(clientMetadataList)
                .extracting(ClientMetadata::getClientId, ClientMetadata::getAppIcon, ClientMetadata::getAppLaunchUrl, ClientMetadata::isShowOnHomePage)
                .contains(Tuple.tuple(clientId3, client3Metadata.getAppIcon(), client3Metadata.getAppLaunchUrl(), client3Metadata.isShowOnHomePage()))
                .contains(Tuple.tuple(clientId4, client4Metadata.getAppIcon(), client4Metadata.getAppLaunchUrl(), client4Metadata.isShowOnHomePage()));
    }

    @Test
    void missingAcceptHeader_isOk() throws Exception {
        mockMvc.perform(get("/oauth/clients/meta")
                        .header("Authorization", "Bearer " + getUserAccessToken(generator.generate())))
                .andExpect(status().isOk());
    }

    @Test
    void wrongAcceptHeader_isNotAcceptable() throws Exception {
        mockMvc.perform(get("/oauth/clients/meta")
                        .header("Authorization", "Bearer " + getUserAccessToken(generator.generate()))
                        .accept(TEXT_PLAIN))
                .andExpect(status().isNotAcceptable());
    }

    @Test
    void updateClientMetadata() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new UaaClientDetails(clientId, null, null, null, null));

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(clientId);
        URL appLaunchUrl = URI.create("http://changed.app.launch/url").toURL();
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        ResultActions perform = performUpdate(updatedClientMetadata);
        assertThat(perform.andReturn().getResponse().getContentAsString()).contains(appLaunchUrl.toString());

        MockHttpServletResponse response = getTestClientMetadata(clientId, adminClientTokenWithClientsRead);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString()).contains(appLaunchUrl.toString());
    }

    private ResultActions performUpdate(ClientMetadata updatedClientMetadata) throws Exception {
        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + updatedClientMetadata.getClientId() + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        return mockMvc.perform(updateClientPut);
    }

    @Test
    void updateClientMetadata_InsufficientScope() throws Exception {
        String clientId = generator.generate();
        String marissaToken = getUserAccessToken(clientId);

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(clientId);
        URL appLaunchUrl = URI.create("http://changed.app.launch/url").toURL();
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + marissaToken)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        MockHttpServletResponse response = mockMvc.perform(updateClientPut).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
    }

    @Test
    void updateClientMetadata_WithNoClientIdInBody() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new UaaClientDetails(clientId, null, null, null, null));

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(null);
        URL appLaunchUrl = URI.create("http://changed.app.launch/url").toURL();
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        ResultActions perform = mockMvc.perform(updateClientPut);
        assertThat(perform.andReturn().getResponse().getContentAsString()).contains(appLaunchUrl.toString());

        MockHttpServletResponse response = getTestClientMetadata(clientId, adminClientTokenWithClientsRead);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(response.getContentAsString()).contains(appLaunchUrl.toString());
    }

    @Test
    void updateClientMetadata_ForNonExistentClient() throws Exception {
        String clientId = generator.generate();

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(clientId);
        URL appLaunchUrl = URI.create("http://changed.app.launch/url").toURL();
        clientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientMetadata));
        ResultActions perform = mockMvc.perform(updateClientPut);
        assertThat(NOT_FOUND.value()).isEqualTo(perform.andReturn().getResponse().getStatus());
    }

    @Test
    void updateClientMetadata_ClientIdMismatch() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new UaaClientDetails(clientId, null, null, null, null));

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId("other-client-id");
        URL appLaunchUrl = URI.create("http://changed.app.launch/url").toURL();
        clientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientMetadata));
        ResultActions perform = mockMvc.perform(updateClientPut);
        assertThat(HttpStatus.BAD_REQUEST.value()).isEqualTo(perform.andReturn().getResponse().getStatus());
    }

    private MockHttpServletResponse getTestClientMetadata(String clientId, String token) throws Exception {
        MockHttpServletRequestBuilder createClientGet = get("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON);
        return mockMvc.perform(createClientGet).andReturn().getResponse();
    }
}
