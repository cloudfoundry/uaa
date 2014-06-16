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
package org.cloudfoundry.identity.uaa.authorization.external;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration(locations = { "classpath:spring/env.xml", "classpath:spring/data-source.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb", "test,mysql",
                "test,oracle" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class LdapGroupMappingAuthorizationManagerTests {

    Log logger = LogFactory.getLog(getClass());

    @Autowired
    private DataSource dataSource;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    private JdbcTemplate template;

    private JdbcScimGroupProvisioning gDB;

    private ScimGroupExternalMembershipManager eDB;

    private LdapGroupMappingAuthorizationManager manager;

    @Before
    public void setup() {
        template = new JdbcTemplate(dataSource);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(template, pagingListFactory);
        eDB = new JdbcScimGroupExternalMembershipManager(template, pagingListFactory);
        ((JdbcScimGroupExternalMembershipManager) eDB).setScimGroupProvisioning(gDB);
        assertEquals(0, gDB.retrieveAll().size());

        gDB.create(new ScimGroup("acme"));
        gDB.create(new ScimGroup("acme.dev"));

        manager = new LdapGroupMappingAuthorizationManager();
        manager.setScimGroupProvisioning(gDB);
        manager.setExternalMembershipManager(eDB);
    }

    @After
    public void cleanup() throws Exception {
        TestUtils.deleteFrom(dataSource, "groups", "external_group_mapping");
    }

    private String getGroupId(String groupName) {
        return gDB.query(String.format("displayName eq \"%s\"", groupName)).get(0).getId();
    }

    @Test
    public void testUserUpdateForExternalGroups() {
        eDB.mapExternalGroup(getGroupId("acme"), "cn=Engineering,ou=groups,dc=example,dc=com");
        eDB.mapExternalGroup(getGroupId("acme"), "cn=HR,ou=groups,dc=example,dc=com");
        eDB.mapExternalGroup(getGroupId("acme"), "cn=mgmt,ou=groups,dc=example,dc=com");

        eDB.mapExternalGroup(getGroupId("acme.dev"), "cn=Engineering,ou=groups,dc=example,dc=com");
        eDB.mapExternalGroup(getGroupId("acme.dev"), "cn=mgmt,ou=groups,dc=example,dc=com");

        String info = "{\"externalGroups.0\": \"cn=Engineering,ou=groups,dc=example,dc=com\", " +
                        "\"externalGroups.1\": \"cn=HR,ou=groups,dc=example,dc=com\", " +
                        "\"externalGroups.2\": \"cn=mgmt,ou=groups,dc=example,dc=com\"}";

        Set<String> updatedScopes = manager.findScopesFromAuthorities(info);
        assertTrue(updatedScopes.contains("acme"));
        assertTrue(updatedScopes.contains("acme.dev"));
    }

}
