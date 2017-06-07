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
package org.cloudfoundry.identity.uaa.authorization.external;

import org.cloudfoundry.identity.uaa.authorization.LdapGroupMappingAuthorizationManager;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.LdapAuthority;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.collection.IsArrayContainingInAnyOrder.arrayContainingInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class LdapGroupMappingAuthorizationManagerTests extends JdbcTestBase {

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
    public void initLdapGroupMappingAuthorizationManagerTests() throws Exception {
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);
        gDB = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        eDB = new JdbcScimGroupExternalMembershipManager(jdbcTemplate);
        ((JdbcScimGroupExternalMembershipManager) eDB).setScimGroupProvisioning(gDB);
        assertEquals(0, gDB.retrieveAll(IdentityZoneHolder.get().getId()).size());

        gDB.create(new ScimGroup(null, "acme", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());
        gDB.create(new ScimGroup(null, "acme.dev", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

        bootstrap = new ScimExternalGroupBootstrap(gDB, eDB);

        manager = new LdapGroupMappingAuthorizationManager();
        manager.setScimGroupProvisioning(gDB);
        manager.setExternalMembershipManager(eDB);

        Map<String, Map<String, List>> originMap = new HashMap<>();
        Map<String, List> externalGroupMap = new HashMap<>();
        externalGroupMap.put("cn=Engineering,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=HR,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=mgmt,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=Engineering,ou=groups,dc=example,dc=com", Collections.singletonList("acme.dev"));
        originMap.put(OriginKeys.LDAP, externalGroupMap);
        bootstrap.setExternalGroupMaps(originMap);
        bootstrap.afterPropertiesSet();

        ldapGroups = new HashSet<>(Arrays.asList(new LdapAuthority[] {la1,la2,la3}));
        nonLdapGroups = new HashSet<>(Arrays.asList(new SimpleGrantedAuthority[] {sa1,sa2,sa3}));
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
