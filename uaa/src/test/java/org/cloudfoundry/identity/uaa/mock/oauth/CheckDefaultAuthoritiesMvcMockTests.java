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
package org.cloudfoundry.identity.uaa.mock.oauth;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.ClientRegistrationService;

import java.util.Set;

public class CheckDefaultAuthoritiesMvcMockTests extends InjectedMockContextTest {

    ClientRegistrationService clientRegistrationService;
    private Set<String> defaultAuthorities;

    @Before
    public void setUp() throws Exception {
        clientRegistrationService = getWebApplicationContext().getBean(ClientRegistrationService.class);

        defaultAuthorities = (Set<String>) getWebApplicationContext().getBean("defaultUserAuthorities");
    }

    @Test
    public void testDefaultAuthorities() throws Exception {
        Assert.assertEquals(10, defaultAuthorities.size());
        String[] expected = new String[] {
            "openid",
            "scim.me",
            "cloud_controller.read",
            "cloud_controller.write",
            "cloud_controller_service_permissions.read",
            "password.write",
            "scim.userids",
            "uaa.user",
            "approvals.me",
            "oauth.approvals"
        };
        for (String s : expected) {
            Assert.assertTrue("Expecting authority to be present:"+s,defaultAuthorities.contains(s));
        }
    }
}