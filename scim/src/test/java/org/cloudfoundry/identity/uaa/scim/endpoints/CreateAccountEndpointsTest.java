/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.rest.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class CreateAccountEndpointsTest {

    private MockMvc mockMvc;
    private ScimUserProvisioning scimUserProvisioning;
    private ExpiringCodeStore expiringCodeStore;
    private QueryableResourceManager<ClientDetails> clientDetailsService;

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = Mockito.mock(ScimUserProvisioning.class);
        expiringCodeStore = Mockito.mock(ExpiringCodeStore.class);
        clientDetailsService = Mockito.mock(QueryableResourceManager.class);
        CreateAccountEndpoints controller = new CreateAccountEndpoints(new ObjectMapper(), clientDetailsService, scimUserProvisioning, expiringCodeStore);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    public void testCreatingAnAccountWithAValidCode() throws Exception {
        Mockito.when(expiringCodeStore.retrieveCode("secret_code"))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis()), "{\"username\":\"user@example.com\",\"client_id\":\"app\"}"));

        BaseClientDetails clientDetails = new BaseClientDetails();
        Map<String, String> additionalInformation = new HashMap<>();
        additionalInformation.put(CreateAccountEndpoints.SIGNUP_REDIRECT_URL, "app_callback_url");
        clientDetails.setAdditionalInformation(additionalInformation);

        Mockito.when(clientDetailsService.retrieve("app"))
            .thenReturn(clientDetails);

        Mockito.when(scimUserProvisioning.createUser(any(ScimUser.class), eq("secret")))
            .thenAnswer(new Answer<ScimUser>() {
                @Override
                public ScimUser answer(InvocationOnMock invocationOnMock) throws Throwable {
                    ScimUser u = (ScimUser) invocationOnMock.getArguments()[0];
                    u.setId("newly-created-user-id");
                    return u;
                }
            });

        MockHttpServletRequestBuilder post = post("/create_account")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"password\":\"secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user_id").exists())
                .andExpect(jsonPath("$.username").value("user@example.com"))
                .andExpect(jsonPath("$.redirect_location").value("app_callback_url"));

        ArgumentCaptor<ScimUser> scimUserCaptor = ArgumentCaptor.forClass(ScimUser.class);
        Mockito.verify(scimUserProvisioning).createUser(scimUserCaptor.capture(), eq("secret"));
        Assert.assertEquals("user@example.com", scimUserCaptor.getValue().getUserName());
        Assert.assertEquals("user@example.com", scimUserCaptor.getValue().getPrimaryEmail());
        Assert.assertEquals("newly-created-user-id", scimUserCaptor.getValue().getId());
        Assert.assertEquals(Origin.UAA, scimUserCaptor.getValue().getOrigin());
    }

    @Test
    public void testCreatingAnAccountWithAnInvalidCode() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"emailed_code\",\"password\":\"secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testCreatingAnAccountWhenTheEmailAlreadyExists() throws Exception {
        Mockito.when(expiringCodeStore.retrieveCode("secret_code"))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis()), "{\"username\":\"user@example.com\",\"client_id\":\"login\"}"));

        Mockito.when(clientDetailsService.retrieve("login"))
            .thenReturn(new BaseClientDetails());

        Mockito.when(scimUserProvisioning.createUser(any(ScimUser.class), eq("secret")))
                .thenThrow(new ScimResourceAlreadyExistsException("User already exists"));

        MockHttpServletRequestBuilder post = post("/create_account")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"password\":\"secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isConflict());
    }
}
