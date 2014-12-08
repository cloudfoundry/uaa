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

import static org.hamcrest.collection.IsArrayContainingInAnyOrder.arrayContainingInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.ldap.extension.LdapAuthority;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
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
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration(locations = { "classpath:spring/env.xml", "classpath:spring/data-source.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "default", "hsqldb", "test,postgresql", "test,mysql","test,oracle" })
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

    private ScimExternalGroupBootstrap bootstrap;

    private Set<? extends GrantedAuthority> nonLdapGroups;

    private Set<? extends GrantedAuthority> ldapGroups;

    private LdapAuthority
        la1 = new LdapAuthority("engineering","cn=Engineering,ou=groups,dc=example,dc=com"),
        la2 = new LdapAuthority("HR","cn=HR,ou=groups,dc=example,dc=com"),
        la3 = new LdapAuthority("mgmt","cn=mgmt,ou=groups,dc=example,dc=com");

    private SimpleGrantedAuthority
        sa1 = new SimpleGrantedAuthority("acme"),
        sa2 = new SimpleGrantedAuthority("acme.dev"),
        sa3 = new SimpleGrantedAuthority("acme.notmapped");

    @Before
    public void setup() throws Exception {
        template = new JdbcTemplate(dataSource);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(template, pagingListFactory);
        eDB = new JdbcScimGroupExternalMembershipManager(template, pagingListFactory);
        ((JdbcScimGroupExternalMembershipManager) eDB).setScimGroupProvisioning(gDB);
        assertEquals(0, gDB.retrieveAll().size());

        gDB.create(new ScimGroup("acme"));
        gDB.create(new ScimGroup("acme.dev"));

        bootstrap = new ScimExternalGroupBootstrap(gDB, eDB);

        manager = new LdapGroupMappingAuthorizationManager();
        manager.setScimGroupProvisioning(gDB);
        manager.setExternalMembershipManager(eDB);

        Set<String> externalGroupSet = new HashSet<String>();
        externalGroupSet.add("acme|cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com cn=mgmt,ou=groups,dc=example,dc=com");
        externalGroupSet.add("acme.dev|cn=Engineering,ou=groups,dc=example,dc=com");
        bootstrap.setExternalGroupMap(externalGroupSet);
        bootstrap.afterPropertiesSet();

        ldapGroups = new HashSet<>(Arrays.asList(new LdapAuthority[] {la1,la2,la3}));
        nonLdapGroups = new HashSet<>(Arrays.asList(new SimpleGrantedAuthority[] {sa1,sa2,sa3}));
    }

    @After
    public void cleanup() throws Exception {
        TestUtils.deleteFrom(dataSource, "groups", "external_group_mapping");
    }

    private String getGroupId(String groupName) {
        return gDB.query(String.format("displayName eq \"%s\"", groupName)).get(0).getId();
    }

    @Test
    public void testAllLdapGroups() throws Exception {
        Set<? extends GrantedAuthority> result = manager.findScopesFromAuthorities(ldapGroups);
        String[] list = getAuthorities(Arrays.asList(sa1,sa2));
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(result)));
    }

    @Test
    public void testAllNonLdapGroups() throws Exception {
        Set<? extends GrantedAuthority> result = manager.findScopesFromAuthorities(nonLdapGroups);
        String[] list = getAuthorities(Arrays.asList(sa1,sa2,sa3));
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(result)));
    }

    @Test
    public void testMixedGroups() throws Exception {
        Set<GrantedAuthority> mixed = new HashSet<>();
        mixed.add(sa1);
        mixed.add(sa3);
        mixed.add(la1);
        Set<? extends GrantedAuthority> result = manager.findScopesFromAuthorities(nonLdapGroups);
        String[] list = getAuthorities(Arrays.asList(sa1,sa2,sa3));
        assertThat(list, arrayContainingInAnyOrder(getAuthorities(result)));
    }


    public String[] getAuthorities(Collection<? extends GrantedAuthority> authorities) {
        String[] result = new String[authorities!=null?authorities.size():0];
        if (result.length>0) {
            int index=0;
            for (GrantedAuthority a : authorities) {
                result[index++] = a.getAuthority();
            }
        }
        return result;
    }

}
