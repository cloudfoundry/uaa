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
package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

public class ScimGroupBootstrapTests extends JdbcTestBase {

    private JdbcScimGroupProvisioning gDB;

    private JdbcScimUserProvisioning uDB;

    private JdbcScimGroupMembershipManager mDB;

    private ScimGroupBootstrap bootstrap;

    @Before
    public void initScimGroupBootstrapTests() {
        JdbcTemplate template = jdbcTemplate;
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(template, pagingListFactory);
        uDB = new JdbcScimUserProvisioning(template, pagingListFactory);
        mDB = new JdbcScimGroupMembershipManager(template);
        mDB.setScimGroupProvisioning(gDB);
        mDB.setScimUserProvisioning(uDB);

        uDB.createUser(TestUtils.scimUserInstance("dev1"), "test", IdentityZoneHolder.get().getId());
        uDB.createUser(TestUtils.scimUserInstance("dev2"), "test", IdentityZoneHolder.get().getId());
        uDB.createUser(TestUtils.scimUserInstance("dev3"), "test", IdentityZoneHolder.get().getId());
        uDB.createUser(TestUtils.scimUserInstance("qa1"), "test", IdentityZoneHolder.get().getId());
        uDB.createUser(TestUtils.scimUserInstance("qa2"), "test", IdentityZoneHolder.get().getId());
        uDB.createUser(TestUtils.scimUserInstance("mgr1"), "test", IdentityZoneHolder.get().getId());
        uDB.createUser(TestUtils.scimUserInstance("hr1"), "test", IdentityZoneHolder.get().getId());

        assertEquals(7, uDB.retrieveAll(IdentityZoneHolder.get().getId()).size());
        assertEquals(0, gDB.retrieveAll(IdentityZoneHolder.get().getId()).size());

        bootstrap = new ScimGroupBootstrap(gDB, uDB, mDB);
    }

    @Test
    public void canAddGroups() throws Exception {
        bootstrap.setGroups(StringUtils.commaDelimitedListToSet("org1.dev,org1.qa,org1.engg,org1.mgr,org1.hr").stream().collect(new MapCollector<>(s -> s, s -> null)));
        bootstrap.afterPropertiesSet();
        assertEquals(5, gDB.retrieveAll(IdentityZoneHolder.get().getId()).size());
        assertNotNull(bootstrap.getGroup("org1.dev"));
        assertNotNull(bootstrap.getGroup("org1.qa"));
        assertNotNull(bootstrap.getGroup("org1.engg"));
        assertNotNull(bootstrap.getGroup("org1.mgr"));
        assertNotNull(bootstrap.getGroup("org1.hr"));
    }

    @Test
    public void testNullGroups() throws Exception {
        bootstrap.setGroups(null);
        bootstrap.afterPropertiesSet();
        assertEquals(0, gDB.retrieveAll(IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void canAddMembers() throws Exception {
        bootstrap.setGroupMembers(Arrays.asList(
                        "org1.dev|dev1,dev2,dev3",
                        "org1.dev|hr1,mgr1|write",
                        "org1.qa|qa1,qa2,qa3",
                        "org1.mgr|mgr1",
                        "org1.hr|hr1",
                        "org1.engg|org1.dev,org1.qa,org1.mgr"
                        ));
        bootstrap.afterPropertiesSet();

        assertEquals(5, gDB.retrieveAll(IdentityZoneHolder.get().getId()).size());
        assertEquals(7, uDB.retrieveAll(IdentityZoneHolder.get().getId()).size());
        assertEquals(2, bootstrap.getGroup("org1.qa").getMembers().size());
        assertEquals(1, bootstrap.getGroup("org1.hr").getMembers().size());
        assertEquals(3, bootstrap.getGroup("org1.engg").getMembers().size());
        assertEquals(2, mDB.getMembers(bootstrap.getGroup("org1.dev").getId(), ScimGroupMember.Role.WRITER, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    public void stripsWhitespaceFromGroupNamesAndDescriptions() throws Exception {
        Map<String, String> groups = new HashMap<>();
        groups.put("print", "Access the network printer");
        groups.put("   something", "        Do something else");
        bootstrap.setGroups(groups);
        bootstrap.afterPropertiesSet();

        ScimGroup group;
        assertNotNull(group = bootstrap.getGroup("something"));
        assertNotNull(group = gDB.retrieve(group.getId(), IdentityZoneHolder.get().getId()));
        assertEquals("something", group.getDisplayName());
        assertEquals("Do something else", group.getDescription());
    }

    @Test
    public void fallsBackToMessagesProperties() throws Exception {
        // set up default groups
        HashMap<String, Object> defaultDescriptions = new HashMap<>();
        defaultDescriptions.put("pets.cat", "Access the cat");
        defaultDescriptions.put("pets.dog", "Dog your data");
        defaultDescriptions.put("pony", "The magic of friendship");
        bootstrap.setMessageSource(new MapPropertySource("messages.properties", defaultDescriptions));

        bootstrap.setMessagePropertyNameTemplate("%s");
        bootstrap.setNonDefaultUserGroups(Collections.singleton("pets.cat"));
        bootstrap.setDefaultUserGroups(Collections.singleton("pets.dog"));

        Map<String, String> groups = new HashMap<>();
        groups.put("pony", "");
        bootstrap.setGroups(groups);

        bootstrap.afterPropertiesSet();

        List<ScimGroup> bootstrappedGroups = gDB.retrieveAll(IdentityZoneHolder.get().getId());

        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "pets.cat".equals(group.getDisplayName()) && "Access the cat".equals(group.getDescription())));
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "pets.dog".equals(group.getDisplayName()) && "Dog your data".equals(group.getDescription())));
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "pony".equals(group.getDisplayName()) && "The magic of friendship".equals(group.getDescription())));

    }

    @Test
    public void prefersNonBlankYmlOverMessagesProperties() throws Exception {
        // set up default groups
        HashMap<String, Object> defaults = new HashMap<>();
        defaults.put("records.read", "");
        defaults.put("pets.cat", "Access the cat");
        defaults.put("pets.dog", "Dog your data");

        HashMap<String, Object> nonDefaultUserGroups = new HashMap<>();
        nonDefaultUserGroups.put("water.drink", "hint");

        bootstrap.setMessageSource(new MapPropertySource("messages.properties", defaults));
        bootstrap.setMessagePropertyNameTemplate("%s");
        bootstrap.setNonDefaultUserGroups(nonDefaultUserGroups.keySet());
        bootstrap.setDefaultUserGroups(defaults.keySet());

        Map<String, String> groups = new HashMap<>();
        groups.put("print", "Access the network printer");
        groups.put("records.read", "Read important data");
        groups.put("pets.cat", "Pet the cat");
        groups.put("pets.dog", null);
        groups.put("fish.nemo", null);
        groups.put("water.drink", "Drink the water");
        // set up configured groups
        bootstrap.setGroups(groups);

        bootstrap.afterPropertiesSet();

        List<ScimGroup> bootstrappedGroups = gDB.retrieveAll(IdentityZoneHolder.get().getId());

        // print: only specified in the configured groups, so it should get its description from there
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "print".equals(group.getDisplayName()) && "Access the network printer".equals(group.getDescription())));
        // records.read: exists in the message property source but should get its description from configuration
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "records.read".equals(group.getDisplayName()) && "Read important data".equals(group.getDescription())));
        // pets.cat: read: exists in the message property source but should get its description from configuration
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "pets.cat".equals(group.getDisplayName()) && "Pet the cat".equals(group.getDescription())));
        // pets.dog: specified in configuration with no description, so it should retain the default description
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "pets.dog".equals(group.getDisplayName()) && "Dog your data".equals(group.getDescription())));
        // fish.nemo: never gets a description
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "fish.nemo".equals(group.getDisplayName()) && group.getDescription() == null));
        assertThat(bootstrappedGroups, PredicateMatcher.<ScimGroup>has(group -> "water.drink".equals(group.getDisplayName()) && "Drink the water".equals(group.getDescription())));
    }
}
