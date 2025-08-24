package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpoints;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.validation.AbstractBindingResult;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DefaultTestContext
public class TestZonifyGroupSchema_V2_4_1 {
    private static final int ENTITY_COUNT = 5;

    @Autowired
    public WebApplicationContext webApplicationContext;

    @BeforeEach
    void populateDataUsingEndpoints() {

        RandomValueStringGenerator generator = new RandomValueStringGenerator(16);

        Map<IdentityZone, List<ScimGroup>> zones = new HashMap<>();

        for (int i = 0; i < ENTITY_COUNT; i++) {
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
            for (int j = 0; j < ENTITY_COUNT; j++) {
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
            for (int i = 0; i < ENTITY_COUNT; i++) {
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
                    group.setMembers(Collections.singletonList(member));
                    webApplicationContext.getBean(ScimGroupEndpoints.class).updateGroup(group, group.getId(), String.valueOf(group.getVersion()), new MockHttpServletResponse());
                } finally {
                    IdentityZoneHolder.clear();
                }

            }
            zoneUsers.put(zone.getKey(), users);
        }
    }

    @Test
    void ensure_that_new_fields_not_null() throws Exception {
        JdbcTemplate jdbcTemplate = webApplicationContext.getBean(JdbcTemplate.class);
        DbUtils dbUtils = webApplicationContext.getBean(DbUtils.class);
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM external_group_mapping WHERE origin IS NULL", Integer.class)).isZero();
        assertThat(jdbcTemplate.queryForObject("SELECT count(*) FROM " + dbUtils.getQuotedIdentifier("groups", jdbcTemplate) + " WHERE identity_zone_id IS NULL", Integer.class)).isZero();
    }
}
