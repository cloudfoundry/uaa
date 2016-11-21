/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.junit.After;
import org.junit.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

public class DisableInternalUserManagementFilterMockMvcTests extends InjectedMockContextTest{

    @After
    public void resetInternalUserManagement() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(false, getWebApplicationContext());
    }

    @Test
    public void createAccountNotEnabled() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(true, getWebApplicationContext());

        getMockMvc().perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[@href='/create_account']").doesNotExist());
    }

    @Test
    public void resetPasswordNotEnabled() throws Exception {
        MockMvcUtils.setDisableInternalUserManagement(true, getWebApplicationContext());

        getMockMvc().perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[@href='/forgot_password']").doesNotExist());
    }
}
