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
package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URL;
import java.util.ArrayList;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_PLAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class ClientMetadataAdminEndpointsMockMvcTest extends InjectedMockContextTest {

    private String adminClientTokenWithClientsWrite;
    private MultitenantJdbcClientDetailsService clients;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private UaaTestAccounts testAccounts;
    private String adminClientTokenWithClientsRead;

    @Before
    public void setUp() throws Exception {
        testAccounts = UaaTestAccounts.standard(null);
        adminClientTokenWithClientsRead = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.read");
        adminClientTokenWithClientsWrite = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.write");

        clients = getWebApplicationContext().getBean(MultitenantJdbcClientDetailsService.class);
    }

    @Test
    public void getClientMetadata() throws Exception {
        String clientId = generator.generate();

        String marissaToken = getUserAccessToken(clientId);
        MockHttpServletResponse response = getTestClientMetadata(clientId, marissaToken);

        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
    }

    private String getUserAccessToken(String clientId) throws Exception {
        BaseClientDetails newClient = new BaseClientDetails(clientId, "oauth", "oauth.approvals", "password", "oauth.login");
        newClient.setClientSecret("secret");
        clients.addClientDetails(newClient);
        return testClient.getUserOAuthAccessToken(clientId, "secret", "marissa", "koala", "oauth.approvals");
    }

    @Test
    public void getClientMetadata_WhichDoesNotExist() throws Exception {
        String clientId = generator.generate();

        MockHttpServletResponse response = getTestClientMetadata(clientId, adminClientTokenWithClientsRead);

        assertThat(response.getStatus(), is(HttpStatus.NOT_FOUND.value()));
    }

    @Test
    public void getAllClientMetadata() throws Exception {
        String clientId1 = generator.generate();
        String marissaToken = getUserAccessToken(clientId1);

        String clientId2 = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId2, null, null, null, null));

        String clientId3 = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId3, null, null, null, null));
        ClientMetadata client3Metadata = new ClientMetadata();
        client3Metadata.setClientId(clientId3);
        client3Metadata.setIdentityZoneId("uaa");
        client3Metadata.setAppLaunchUrl(new URL("http://client3.com/app"));
        client3Metadata.setShowOnHomePage(true);
        client3Metadata.setAppIcon("Y2xpZW50IDMgaWNvbg==");
        performUpdate(client3Metadata);

        String clientId4 = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId4, null, null, null, null));
        ClientMetadata client4Metadata = new ClientMetadata();
        client4Metadata.setClientId(clientId4);
        client4Metadata.setIdentityZoneId("uaa");
        client4Metadata.setAppLaunchUrl(new URL("http://client4.com/app"));
        client4Metadata.setAppIcon("aWNvbiBmb3IgY2xpZW50IDQ=");
        performUpdate(client4Metadata);

        MockHttpServletResponse response = getMockMvc().perform(get("/oauth/clients/meta")
            .header("Authorization", "Bearer " + marissaToken)
            .accept(APPLICATION_JSON)).andExpect(status().isOk()).andReturn().getResponse();
        ArrayList<ClientMetadata> clientMetadataList = JsonUtils.readValue(response.getContentAsString(), new TypeReference<ArrayList<ClientMetadata>>() {});

        assertThat(clientMetadataList, not(PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId1))));
        assertThat(clientMetadataList, not(PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId2))));
        assertThat(clientMetadataList, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId3) && m.getAppIcon().equals(client3Metadata.getAppIcon()) && m.getAppLaunchUrl().equals(client3Metadata.getAppLaunchUrl()) && m.isShowOnHomePage() == client3Metadata.isShowOnHomePage()));
        assertThat(clientMetadataList, PredicateMatcher.<ClientMetadata>has(m -> m.getClientId().equals(clientId4) && m.getAppIcon().equals(client4Metadata.getAppIcon()) && m.getAppLaunchUrl().equals(client4Metadata.getAppLaunchUrl()) && m.isShowOnHomePage() == client4Metadata.isShowOnHomePage()));
    }

    @Test
    public void missingAcceptHeader_isOk() throws Exception {
        getMockMvc().perform(get("/oauth/clients/meta")
                .header("Authorization", "Bearer " + getUserAccessToken(generator.generate())))
                .andExpect(status().isOk());
    }

    @Test
    public void wrongAcceptHeader_isNotAcceptable() throws Exception {
        getMockMvc().perform(get("/oauth/clients/meta")
                .header("Authorization", "Bearer " + getUserAccessToken(generator.generate()))
                .accept(TEXT_PLAIN))
                .andExpect(status().isNotAcceptable());
    }

    @Test
    public void updateClientMetadata() throws Exception {
        String clientId = generator.generate();
        clients.addClientDetails(new BaseClientDetails(clientId, null, null, null, null));

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(clientId);
        URL appLaunchUrl = new URL("http://changed.app.launch/url");
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        ResultActions perform = performUpdate(updatedClientMetadata);
        assertThat(perform.andReturn().getResponse().getContentAsString(), containsString(appLaunchUrl.toString()));

        MockHttpServletResponse response = getTestClientMetadata(clientId, adminClientTokenWithClientsRead);
        assertThat(response.getStatus(), is(HttpStatus.OK.value()));
        assertThat(response.getContentAsString(), containsString(appLaunchUrl.toString()));
    }

    private ResultActions performUpdate(ClientMetadata updatedClientMetadata) throws Exception {
        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + updatedClientMetadata.getClientId() + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithClientsWrite)
                .header("If-Match", "0")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        return getMockMvc().perform(updateClientPut);
    }

    @Test
    public void updateClientMetadata_InsufficientScope() throws Exception {
        String clientId = generator.generate();
        String marissaToken = getUserAccessToken(clientId);

        ClientMetadata updatedClientMetadata = new ClientMetadata();
        updatedClientMetadata.setClientId(clientId);
        URL appLaunchUrl = new URL("http://changed.app.launch/url");
        updatedClientMetadata.setAppLaunchUrl(appLaunchUrl);

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/" + clientId + "/meta")
            .header("Authorization", "Bearer " + marissaToken)
            .header("If-Match", "0")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(updatedClientMetadata));
        MockHttpServletResponse response = getMockMvc().perform(updateClientPut).andReturn().getResponse();
        assertThat(response.getStatus(), is(HttpStatus.FORBIDDEN.value()));
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

        MockHttpServletResponse response = getTestClientMetadata(clientId, adminClientTokenWithClientsRead);
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

    private MockHttpServletResponse getTestClientMetadata(String clientId, String token) throws Exception {
        MockHttpServletRequestBuilder createClientGet = get("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON);
        return getMockMvc().perform(createClientGet).andReturn().getResponse();
    }
}
