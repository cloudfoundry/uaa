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

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListenerExtension;
import org.cloudfoundry.identity.uaa.test.HoneycombJdbcInterceptorExtension;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.junit.Assert;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import java.util.Set;
@ExtendWith(SpringExtension.class)
@ExtendWith(HoneycombJdbcInterceptorExtension.class)
@ExtendWith(HoneycombAuditEventTestListenerExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class CheckDefaultAuthoritiesMvcMockTests {
    @Autowired
    public WebApplicationContext webApplicationContext;

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

    @BeforeEach
    public void setUp() throws Exception {
        clientRegistrationService = webApplicationContext.getBean(ClientServicesExtension.class);

        defaultAuthorities = (Set<String>) webApplicationContext.getBean("defaultUserAuthorities");
    }

    @Test
    public void testDefaultAuthorities() throws Exception {
        Assert.assertEquals(14, defaultAuthorities.size());
        for (String s : EXPECTED_DEFAULT_GROUPS) {
            Assert.assertTrue("Expecting authority to be present:"+s,defaultAuthorities.contains(s));
        }
    }
}