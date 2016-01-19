package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

    private JdbcClientMetaDetailsProvisioning clientUIs;
    private String adminClientTokenWithWrite;
    private JdbcClientDetailsService clients;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private String adminClientTokenWithRead;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        testAccounts = UaaTestAccounts.standard(null);
        adminClientTokenWithRead = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.read");
        adminClientTokenWithWrite = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.write");

        clientUIs = getWebApplicationContext().getBean(JdbcClientMetaDetailsProvisioning.class);
        clients = getWebApplicationContext().getBean(JdbcClientDetailsService.class);
    }

    @Test
    public void create_IsCreated() throws Exception {
        String clientId = generator.generate();

        ClientMetaDetails clientMetaDetails = new ClientMetaDetails();
        clientMetaDetails.setClientId(clientId);

        clients.addClientDetails(new BaseClientDetails(clientId, null, null, null, null));

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithWrite)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientMetaDetails));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
    }

    @Test
    public void create_noClient() throws Exception {
        String clientId = generator.generate();
        ClientMetaDetails clientMetaDetails = new ClientMetaDetails();
        clientMetaDetails.setClientId(clientId);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithWrite)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientMetaDetails));
        getMockMvc().perform(createClientPost).andExpect(status().isNotFound());
    }

    @Test
    public void create_unauthorizedBecauseInsufficientScope() throws Exception {
        // given a token with insufficient privileges
        String userToken = testClient.getUserOAuthAccessToken(
                "app",
                "appclientsecret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                "openid");

        // when a new client is created
        String clientId = generator.generate();
        ClientMetaDetails clientMetaDetails = new ClientMetaDetails();
        clientMetaDetails.setClientId(clientId);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + userToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientMetaDetails));
        MvcResult result = getMockMvc().perform(createClientPost).andReturn();

        // then expect a 403 Forbidden
        assertThat(result.getResponse().getStatus(), is(HttpStatus.FORBIDDEN.value()));
    }

    @Test
    public void get_client() throws Exception {
        String clientId = generator.generate();

        MockHttpServletRequestBuilder createClientPost = get("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminClientTokenWithRead)
                .accept(APPLICATION_JSON);
        MvcResult result = getMockMvc().perform(createClientPost).andReturn();

        // TEMP
        assertThat(result.getResponse().getStatus(), is(HttpStatus.OK.value()));
        assertThat(result.getResponse().getContentAsString(), is(1));
    }
}