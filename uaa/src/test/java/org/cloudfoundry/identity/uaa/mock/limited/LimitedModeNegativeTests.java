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

package org.cloudfoundry.identity.uaa.mock.limited;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.env.MockPropertySource;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Properties;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.resetLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setLimitedModeStatusFile;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class LimitedModeNegativeTests extends InjectedMockContextTest {

    private String adminToken;
    private File statusFile;
    private File existingStatusFile = null;
    private XmlWebApplicationContext webApplicationContext;
    private MockEnvironment mockEnvironment;
    private MockPropertySource propertySource;
    private Properties originalProperties = new Properties();
    Field f = ReflectionUtils.findField(MockEnvironment.class, "propertySource");

    @Before
    public void setUp() throws Exception {
        webApplicationContext = getWebApplicationContext();
        existingStatusFile = getLimitedModeStatusFile(webApplicationContext);
        statusFile = setLimitedModeStatusFile(webApplicationContext);
        mockEnvironment = (MockEnvironment) webApplicationContext.getEnvironment();
        f.setAccessible(true);
        propertySource = (MockPropertySource) ReflectionUtils.getField(f, mockEnvironment);
        for (String s : propertySource.getPropertyNames()) {
            originalProperties.put(s, propertySource.getProperty(s));
        }
        mockEnvironment.setProperty("spring_profiles", "default, degraded");
        adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(getMockMvc(),
                                                                       "admin",
                                                                       "adminsecret",
                                                                       "uaa.admin",
                                                                       null,
                                                                       true);
    }


    @After
    public void tearDown() throws Exception {
        resetLimitedModeStatusFile(webApplicationContext, existingStatusFile);
        mockEnvironment.getPropertySources().remove(MockPropertySource.MOCK_PROPERTIES_PROPERTY_SOURCE_NAME);
        MockPropertySource originalPropertySource = new MockPropertySource(originalProperties);
        ReflectionUtils.setField(f, mockEnvironment, new MockPropertySource(originalProperties));
        mockEnvironment.getPropertySources().addLast(originalPropertySource);
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
                .andExpect(jsonPath("error").value(LimitedModeUaaFilter.ERROR_CODE))
                .andExpect(jsonPath("error_description").value(LimitedModeUaaFilter.ERROR_MESSAGE));
        } else {
            getMockMvc().perform(method)
                .andExpect(status().is(expected.value()));
        }
    }
}
