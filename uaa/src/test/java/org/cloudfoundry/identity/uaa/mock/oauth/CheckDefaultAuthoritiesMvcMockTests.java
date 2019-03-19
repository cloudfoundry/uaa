/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.WebApplicationContext;

import java.util.Set;

@DefaultTestContext
public class CheckDefaultAuthoritiesMvcMockTests {
    @Autowired
    public WebApplicationContext webApplicationContext;

    private Set<String> defaultAuthorities;
    private static final String[] EXPECTED_DEFAULT_GROUPS = new String[]{
            "openid",
            "scim.me",
            "cloud_controller.read",
            "cloud_controller.write",
            "cloud_controller_service_permissions.read",
            "password.write",
            "scim.userids",
            "uaa.user",
            "approvals.me",
            "oauth.approvals",
            "profile",
            "roles",
            "user_attributes",
            "uaa.offline_token"
    };

    @BeforeEach
    void setUp() {
        defaultAuthorities = (Set<String>) webApplicationContext.getBean("defaultUserAuthorities");
    }

    @Test
    void testDefaultAuthorities() {
        Assert.assertEquals(14, defaultAuthorities.size());
        for (String s : EXPECTED_DEFAULT_GROUPS) {
            Assert.assertTrue("Expecting authority to be present:" + s, defaultAuthorities.contains(s));
        }
    }
}