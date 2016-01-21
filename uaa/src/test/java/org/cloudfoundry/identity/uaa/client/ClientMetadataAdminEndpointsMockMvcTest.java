package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URL;
import java.util.ArrayList;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class ClientMetadataAdminEndpointsMockMvcTest extends InjectedMockContextTest {

    private String adminClientTokenWithClientsWrite;
    private JdbcClientDetailsService clients;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private String adminClientTokenWithClientsRead;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        testAccounts = UaaTestAccounts.standard(null);
        adminClientTokenWithClientsRead = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.read");
        adminClientTokenWithClientsWrite = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.write");

        clients = getWebApplicationContext().getBean(JdbcClientDetailsService.class);
    }

    @Test
    public void getClientMetadata() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId, null, null, null, null));

        MockHttpServletResponse response = getTestClientMetadata(clientId);

        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
    }
    
    @Test
    public void getClientMetadata_WhichDoesNotExist() throws Exception {
        String clientId = generator.generate();

        MockHttpServletResponse response = getTestClientMetadata(clientId);

        assertThat(response.getStatus(), is(HttpStatus.NOT_FOUND.value()));
    }

    @Test
    public void retrieveAllClientMetadata() throws Exception {
        String clientId1 = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId1, null, null, null, null));

        String clientId2 = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId2, null, null, null, null));

        String clientId3 = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId3, null, null, null, null));

        MockHttpServletResponse response = getMockMvc().perform(get("/oauth/clients/meta")
            .header("Authorization", "Bearer " + adminClientTokenWithClientsRead)
            .accept(APPLICATION_JSON)).andReturn().getResponse();
        ArrayList<ClientMetadata> clientMetadataList = JsonUtils.readValue(response.getContentAsString(), new TypeReference<ArrayList<ClientMetadata>>() {});

        assertThat(clientMetadataList, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId1)));
        assertThat(clientMetadataList, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId2)));
        assertThat(clientMetadataList, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId3)));
    }

    @Test
    public void updateClientMetadata() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId, null, null, null, null));

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(clientId);
        URL appLaunchUrl = new URL("http://changed.app.launch/url");
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        ResultActions perform = getMockMvc().perform(updateClientPut);
        assertThat(perform.andReturn().getResponse().getContentAsString(), containsString(appLaunchUrl.toString()));

        MockHttpServletResponse response = getTestClientMetadata(clientId);
        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
        assertThat(response.getContentAsString(), containsString(appLaunchUrl.toString()));
    }

    @Test
    public void updateClientMetadata_WithNoClientIdInBody() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId, null, null, null, null));

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(null);
        URL appLaunchUrl = new URL("http://changed.app.launch/url");
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
            .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
            .header("If-Match", "0")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        ResultActions perform = getMockMvc().perform(updateClientPut);
        assertThat(perform.andReturn().getResponse().getContentAsString(), containsString(appLaunchUrl.toString()));

        MockHttpServletResponse response = getTestClientMetadata(clientId);
        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
        assertThat(response.getContentAsString(), containsString(appLaunchUrl.toString()));
    }

    @Test
    public void updateClientMetadata_ForNonExistentClient() throws Exception {
        String clientId = generator.generate();

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(clientId);
        URL appLaunchUrl = new URL("http://changed.app.launch/url");
        clientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
            .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
            .header("If-Match", "0")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(clientMetadata));
        ResultActions perform = getMockMvc().perform(updateClientPut);
        assertEquals(perform.andReturn().getResponse().getStatus(), NOT_FOUND.value());
    }

    @Test
    public void updateClientMetadata_ClientIdMismatch() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId, null, null, null, null));

        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId("other-client-id");
        URL appLaunchUrl = new URL("http://changed.app.launch/url");
        clientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
            .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
            .header("If-Match", "0")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(clientMetadata));
        ResultActions perform = getMockMvc().perform(updateClientPut);
        assertEquals(perform.andReturn().getResponse().getStatus(), HttpStatus.BAD_REQUEST.value());
    }

    private MockHttpServletResponse getTestClientMetadata(String clientId) throws Exception {
        MockHttpServletRequestBuilder createClientGet = get("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsRead)
                .accept(APPLICATION_JSON);
        return getMockMvc().perform(createClientGet).andReturn().getResponse();
    }
}
