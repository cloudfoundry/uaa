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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.Arrays;

public class PasswordResetEndpointsTest {

    private MockMvc mockMvc;
    private ScimUserProvisioning scimUserProvisioning;
    private ExpiringCodeStore expiringCodeStore;

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = Mockito.mock(ScimUserProvisioning.class);
        expiringCodeStore = Mockito.mock(ExpiringCodeStore.class);
        PasswordResetEndpoints controller = new PasswordResetEndpoints(scimUserProvisioning, expiringCodeStore);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        Mockito.when(expiringCodeStore.generateCode(eq("id001"), any(Timestamp.class)))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + 1000), "id001"));
    }

    @Test
    public void testCreatingAPasswordResetWhenTheEmailExists() throws Exception {
        ScimUser user = new ScimUser("id001", "userman", null, null);
        user.addEmail("user@example.com");
        Mockito.when(scimUserProvisioning.query("email eq 'user@example.com'"))
                .thenReturn(Arrays.asList(user));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(content().string("secret_code"));
    }

    @Test
    public void testCreatingAPasswordResetWhenTheUserDoesNotExist() throws Exception {
        Mockito.when(scimUserProvisioning.query("email eq 'user@example.com'"))
                .thenReturn(Arrays.<ScimUser>asList());

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testChangingAPasswordWithAValidCode() throws Exception {
        Mockito.when(expiringCodeStore.retrieveCode("secret_code"))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis()), "eyedee"));

        Mockito.when(scimUserProvisioning.changePassword("eyedee", null, "new_secret")).thenReturn(true);

        ScimUser scimUser = new ScimUser("eyedee", "userman", "User", "Man");
        scimUser.addEmail("user@example.com");
        Mockito.when(scimUserProvisioning.retrieve("eyedee")).thenReturn(scimUser);

        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(content().string("userman"));
    }
}
