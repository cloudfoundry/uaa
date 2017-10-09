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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Set;

public class CheckDefaultAuthoritiesMvcMockTests extends InjectedMockContextTest {

    ClientServicesExtension clientRegistrationService;
    private Set<String> defaultAuthorities;
    public static final String[] EXPECTED_DEFAULT_GROUPS = new String[]{
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

    @Before
    public void setUp() throws Exception {
        clientRegistrationService = getWebApplicationContext().getBean(ClientServicesExtension.class);

        defaultAuthorities = (Set<String>) getWebApplicationContext().getBean("defaultUserAuthorities");
    }

    @Test
    public void testDefaultAuthorities() throws Exception {
        Assert.assertEquals(14, defaultAuthorities.size());
        for (String s : EXPECTED_DEFAULT_GROUPS) {
            Assert.assertTrue("Expecting authority to be present:"+s,defaultAuthorities.contains(s));
        }
    }
}