/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventListenerRule;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpoints;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.validation.AbstractBindingResult;
import org.springframework.web.context.WebApplicationContext;

import java.util.*;

import static org.hamcrest.CoreMatchers.is;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class TestZonifyGroupSchema_V2_4_1 {
    public static final int ENTITY_COUNT = 5;
    @Rule
    public HoneycombAuditEventListenerRule honeycombAuditEventListenerRule = new HoneycombAuditEventListenerRule();

    @Autowired
    public WebApplicationContext webApplicationContext;

    @Before
    public void populateDataUsingEndpoints() throws Exception {

        RandomValueStringGenerator generator = new RandomValueStringGenerator(16);

        Map<IdentityZone,List<ScimGroup>> zones = new HashMap<>();


        for (int i=0; i<ENTITY_COUNT; i++) {
            String subdomain = generator.generate();
            IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
            webApplicationContext.getBean(IdentityZoneEndpoints.class).createIdentityZone(zone, new AbstractBindingResult(null) {
                @Override
                public Object getTarget() {
                    return null;
                }

                @Override
                protected Object getActualFieldValue(String field) {
                    return null;
                }
            });
            List<ScimGroup> groups = new LinkedList<>();
            IdentityZoneHolder.set(zone);
            for (int j=0; j<ENTITY_COUNT; j++) {
                ScimGroup group = new ScimGroup(null, generator.generate(), null);
                group = webApplicationContext.getBean(ScimGroupEndpoints.class).createGroup(group, new MockHttpServletResponse());
                groups.add(group);
            }
            zones.put(zone, groups);
            IdentityZoneHolder.clear();
        }



        Map<IdentityZone, List<ScimUser>> zoneUsers = new HashMap<>();
        for (Map.Entry<IdentityZone, List<ScimGroup>> zone : zones.entrySet()) {
            List<ScimUser> users = new LinkedList<>();
            for (int i=0; i<ENTITY_COUNT; i++) {
                String id = generator.generate();
                String email = id + "@test.org";
                ScimUser user = new ScimUser(null, id, id, id);
                user.setPrimaryEmail(email);
                user.setPassword(id);
                try {
                    IdentityZoneHolder.set(zone.getKey());
                    user = webApplicationContext.getBean(ScimUserEndpoints.class).createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
                    users.add(user);
                    ScimGroupMember member = new ScimGroupMember(user.getId());
                    ScimGroup group = webApplicationContext.getBean(ScimGroupEndpoints.class).getGroup(zone.getValue().get(i).getId(), new MockHttpServletResponse());
                    group.setMembers(Arrays.asList(member));
                    webApplicationContext.getBean(ScimGroupEndpoints.class).updateGroup(group, group.getId(),String.valueOf(group.getVersion()), new MockHttpServletResponse());
                }finally {
                    IdentityZoneHolder.clear();
                }

            }
            zoneUsers.put(zone.getKey(), users);
        }


    }


    @Test
    public void test_Ensure_That_New_Fields_NotNull() throws Exception {
        Assert.assertThat(webApplicationContext.getBean(JdbcTemplate.class).queryForObject("SELECT count(*) FROM external_group_mapping WHERE origin IS NULL", Integer.class), is(0));
        Assert.assertThat(webApplicationContext.getBean(JdbcTemplate.class).queryForObject("SELECT count(*) FROM groups WHERE identity_zone_id IS NULL", Integer.class), is(0));
    }

}
