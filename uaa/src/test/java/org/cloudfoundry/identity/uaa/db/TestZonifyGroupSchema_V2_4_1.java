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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpoints;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.validation.AbstractBindingResult;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;

public class TestZonifyGroupSchema_V2_4_1 extends InjectedMockContextTest {

    public static final int ENTITY_COUNT = 5;

    @Before
    public void populateDataUsingEndpoints() throws Exception {

        RandomValueStringGenerator generator = new RandomValueStringGenerator(16);

        Map<IdentityZone,List<ScimGroup>> zones = new HashMap<>();


        for (int i=0; i<ENTITY_COUNT; i++) {
            String subdomain = generator.generate();
            IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
            getWebApplicationContext().getBean(IdentityZoneEndpoints.class).createIdentityZone(zone, new AbstractBindingResult(null) {
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
                group = getWebApplicationContext().getBean(ScimGroupEndpoints.class).createGroup(group, new MockHttpServletResponse());
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
                    user = getWebApplicationContext().getBean(ScimUserEndpoints.class).createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
                    users.add(user);
                    ScimGroupMember member = new ScimGroupMember(user.getId());
                    ScimGroup group = getWebApplicationContext().getBean(ScimGroupEndpoints.class).getGroup(zone.getValue().get(i).getId(), new MockHttpServletResponse());
                    group.setMembers(Arrays.asList(member));
                    getWebApplicationContext().getBean(ScimGroupEndpoints.class).updateGroup(group, group.getId(),String.valueOf(group.getVersion()), new MockHttpServletResponse());
                }finally {
                    IdentityZoneHolder.clear();
                }

            }
            zoneUsers.put(zone.getKey(), users);
        }


    }


    @Test
    public void test_Ensure_That_New_Fields_NotNull() throws Exception {
        Assert.assertThat(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT count(*) FROM external_group_mapping WHERE origin IS NULL", Integer.class), is(0));
        Assert.assertThat(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT count(*) FROM groups WHERE identity_zone_id IS NULL", Integer.class), is(0));
    }

}
