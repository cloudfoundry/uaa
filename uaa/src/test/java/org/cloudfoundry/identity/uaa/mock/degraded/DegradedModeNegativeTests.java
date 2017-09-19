/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.degraded;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.web.DegradedModeUaaFilter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class DegradedModeNegativeTests extends InjectedMockContextTest {

    private boolean degraded;
    private String adminToken;

    @Before
    public void degrade() throws Exception {
        DegradedModeUaaFilter bean = getWebApplicationContext().getBean(DegradedModeUaaFilter.class);
        degraded = bean.isEnabled();
        bean.setEnabled(true);
        adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(getMockMvc(),
                                                                       "admin",
                                                                       "adminsecret",
                                                                       "uaa.admin",
                                                                       null,
                                                                       true);
    }


    @After
    public void upgrade() throws Exception {
        getWebApplicationContext().getBean(DegradedModeUaaFilter.class).setEnabled(degraded);
    }


    @Test
    public void identity_zone_can_read() throws Exception {
        validate(
            get("/identity-zones")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer " + adminToken),
            OK
        );

        validate(
            get("/identity-zones/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer " + adminToken),
            NOT_FOUND);
    }

    @Test
    public void identity_zone_can_not_write() throws Exception {
        validate(
            post("/identity-zones")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(""))
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );

        validate(
            put("/identity-zones/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(""))
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );
    }

    @Test
    public void identity_provider_can_read() throws Exception {
        validate(
            get("/identity-providers")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            OK
        );

        validate(
            get("/identity-providers/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            NOT_FOUND
        );
    }

    @Test
    public void identity_provider_can_not_write() throws Exception {
        validate(
            post("/identity-providers")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );

        validate(
            put("/identity-providers/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );
    }

    @Test
    public void clients_can_read() throws Exception {
        validate(
            get("/oauth/clients")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            OK
        );

        validate(
            get("/oauth/clients/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            NOT_FOUND
        );
    }

    @Test
    public void clients_can_not_write() throws Exception {
        validate(
            post("/oauth/clients")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );

        validate(
            put("/oauth/clients/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );
    }

    @Test
    public void groups_can_read() throws Exception {
        validate(
            get("/Groups")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            OK
        );

        validate(
            get("/Groups/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            NOT_FOUND
        );
    }

    @Test
    public void groups_can_not_write() throws Exception {
        validate(
            post("/Groups")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );

        validate(
            put("/Groups/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );
    }

    @Test
    public void users_can_read() throws Exception {
        validate(
            get("/Users")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            OK
        );

        validate(
            get("/Users/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            NOT_FOUND
        );
    }

    @Test
    public void users_can_not_write() throws Exception {
        validate(
            post("/Users")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );

        validate(
            put("/Users/{id}", "some-invalid-id")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer "+adminToken),
            SERVICE_UNAVAILABLE
        );
    }

    public void validate(MockHttpServletRequestBuilder method, HttpStatus expected) throws Exception {
        if (SERVICE_UNAVAILABLE.equals(expected)) {
            getMockMvc().perform(method)
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("error").value(DegradedModeUaaFilter.ERROR_CODE))
                .andExpect(jsonPath("error_description").value(DegradedModeUaaFilter.ERROR_MESSAGE));
        } else {
            getMockMvc().perform(method)
                .andExpect(status().is(expected.value()));
        }
    }

}
