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
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.io.File;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.*;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class LimitedModeTokenMockMvcTests extends TokenMvcMockTests {

    private File existingStatusFile;

    @BeforeEach
    @Override
    public void setUpContext(
            @Autowired @Qualifier("defaultUserAuthorities") Object defaultAuthorities
    ) throws Exception {
        super.setUpContext(defaultAuthorities);

        existingStatusFile = getLimitedModeStatusFile(webApplicationContext);
        setLimitedModeStatusFile(webApplicationContext);

        assertTrue(isLimitedMode());
    }

    @AfterEach
    void tearDown() throws Exception {
        resetLimitedModeStatusFile(webApplicationContext, existingStatusFile);
    }

    @Test
    void check_token_while_limited() throws Exception {
        BaseClientDetails client = setUpClients(generator.generate().toLowerCase(),
                                                "uaa.resource,clients.read",
                                                "",
                                                "client_credentials",
                                                true);
        String token = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, client.getClientId(), SECRET, null, null, true);
        mockMvc.perform(
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

    private boolean isLimitedMode() {
        return webApplicationContext.getBean(LimitedModeUaaFilter.class).isEnabled();
    }
}
