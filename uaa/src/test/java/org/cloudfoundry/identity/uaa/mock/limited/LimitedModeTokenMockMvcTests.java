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

import org.cloudfoundry.identity.uaa.mock.token.TokenMvcMockTests;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.env.MockPropertySource;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Properties;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.resetLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setLimitedModeStatusFile;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class LimitedModeTokenMockMvcTests extends TokenMvcMockTests {

    private File existingStatusFile;
    private File statusFile;
    private XmlWebApplicationContext webApplicationContext;
    private MockEnvironment mockEnvironment;
    private MockPropertySource propertySource;
    private Properties originalProperties = new Properties();
    Field f = ReflectionUtils.findField(MockEnvironment.class, "propertySource");

    @BeforeClass
    public static void setDegradedProfile() {
        System.setProperty("spring.profiles.active", "default, degraded");
    }

    @Before
    @Override
    public void setUpContext() throws Exception {
        super.setUpContext();
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
    public void check_token_while_limited() throws Exception {
        BaseClientDetails client = setUpClients(generator.generate().toLowerCase(),
                                                "uaa.resource,clients.read",
                                                "",
                                                "client_credentials",
                                                true);
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(getMockMvc(), client.getClientId(), SECRET, null, null, true);
        getMockMvc().perform(
            post("/check_token")
                .param("token", token)
                .header(AUTHORIZATION,
                        "Basic " + new String(Base64.encode((client.getClientId() + ":" + SECRET).getBytes())))
        )
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.scope").value(containsInAnyOrder("clients.read", "uaa.resource")))
            .andExpect(jsonPath("$.client_id").value(client.getClientId()))
            .andExpect(jsonPath("$.jti").value(token));
    }

    @AfterClass
    public static void unsetDegradedProfile() {
        System.clearProperty("spring.profiles.active");
    }
}
