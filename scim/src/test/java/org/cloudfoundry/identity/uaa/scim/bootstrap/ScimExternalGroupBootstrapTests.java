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
package org.cloudfoundry.identity.uaa.scim.bootstrap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.HashSet;
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
@IfProfileValue(name = "spring.profiles.active", values = { "", "default", "hsqldb", "test,postgresql", "test,mysql","test,oracle" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ScimExternalGroupBootstrapTests {

    Log logger = LogFactory.getLog(getClass());

    @Autowired
    private DataSource dataSource;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    private JdbcTemplate template;

    private JdbcScimGroupProvisioning gDB;

    private ScimGroupExternalMembershipManager eDB;

    private ScimExternalGroupBootstrap bootstrap;

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

        bootstrap = new ScimExternalGroupBootstrap(gDB, eDB);
    }

    @After
    public void cleanup() throws Exception {
        TestUtils.deleteFrom(dataSource, "groups", "group_membership", "external_group_mapping");
    }

    @Test
    public void canAddExternalGroups() throws Exception {
        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("acme|cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com cn=mgmt,ou=groups,dc=example,dc=com");
        externalGroupSet.add("acme.dev|cn=Engineering,ou=groups,dc=example,dc=com");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();
        assertEquals(2, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering,ou=groups,dc=example,dc=com").size());
        assertEquals(1, eDB.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com").size());
        assertEquals(1, eDB.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com").size());

        assertEquals(3, eDB.getExternalGroupMapsByGroupName("acme").size());
        assertEquals(1, eDB.getExternalGroupMapsByGroupName("acme.dev").size());
    }

    @Test
    public void canAddExternalGroupsWithSpaces() throws Exception {
        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("acme|   cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com   cn=mgmt,ou=groups,dc=example,dc=com ");
        externalGroupSet.add("acme.dev|cn=Engineering,ou=groups,dc=example,dc=com  ");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();
        assertEquals(2, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering,ou=groups,dc=example,dc=com").size());
        assertEquals(1, eDB.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com").size());
        assertEquals(1, eDB.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com").size());

        assertEquals(3, eDB.getExternalGroupMapsByGroupName("acme").size());
        assertEquals(1, eDB.getExternalGroupMapsByGroupName("acme.dev").size());
    }

    @Test
    public void cannotAddExternalGroupsThatDoNotExist() throws Exception {
        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("acme1|   cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com   cn=mgmt,ou=groups,dc=example,dc=com");
        externalGroupSet.add("acme1.dev|cn=Engineering,ou=groups,dc=example,dc=com");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering,ou=groups,dc=example,dc=com").size());
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com").size());
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com").size());

        assertNull(eDB.getExternalGroupMapsByGroupName("acme1"));
        assertNull(eDB.getExternalGroupMapsByGroupName("acme1.dev"));
    }

    @Test
    public void cannotAddExternalGroupsThatMapToNothing() throws Exception {
        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("acme|");
        externalGroupSet.add("acme.dev");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering,ou=groups,dc=example,dc=com").size());
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com").size());
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com").size());

        assertEquals(0, eDB.getExternalGroupMapsByGroupName("acme").size());
        assertEquals(0, eDB.getExternalGroupMapsByGroupName("acme.dev").size());
    }
}
