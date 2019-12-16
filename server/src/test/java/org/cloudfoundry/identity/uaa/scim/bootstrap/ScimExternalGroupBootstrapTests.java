package org.cloudfoundry.identity.uaa.scim.bootstrap;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@WithDatabaseContext
class ScimExternalGroupBootstrapTests {

    private ScimGroupExternalMembershipManager eDB;

    private ScimExternalGroupBootstrap bootstrap;

    @BeforeEach
    void setUp(
            @Autowired JdbcTemplate jdbcTemplate,
            @Autowired LimitSqlAdapter limitSqlAdapter
    ) {
        IdentityZone zone = new IdentityZone();
        zone.setId(RandomStringUtils.randomAlphabetic(10));
        IdentityZoneHolder.set(zone);

        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);
        JdbcScimGroupProvisioning gDB = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        eDB = new JdbcScimGroupExternalMembershipManager(jdbcTemplate);
        ((JdbcScimGroupExternalMembershipManager) eDB).setScimGroupProvisioning(gDB);
        assertEquals(0, gDB.retrieveAll(IdentityZoneHolder.get().getId()).size());

        gDB.create(new ScimGroup(null, "acme", IdentityZone.getUaaZoneId()), IdentityZoneHolder.get().getId());
        gDB.create(new ScimGroup(null, "acme.dev", IdentityZone.getUaaZoneId()), IdentityZoneHolder.get().getId());

        bootstrap = new ScimExternalGroupBootstrap(gDB, eDB);
    }

    @Test
    void canAddExternalGroups() {
        Map<String, Map<String, List>> originMap = new HashMap<>();
        Map<String, List> externalGroupMap = new HashMap<>();
        externalGroupMap.put("cn=Engineering Department,ou=groups,dc=example,dc=com", Arrays.asList("acme", "acme.dev"));
        externalGroupMap.put("cn=HR,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=mgmt,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        originMap.put(OriginKeys.LDAP, externalGroupMap);
        bootstrap.setExternalGroupMaps(originMap);
        bootstrap.afterPropertiesSet();

        assertEquals(2, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering Department,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
        assertEquals(1, eDB.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
        assertEquals(1, eDB.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());

        assertEquals(3, eDB.getExternalGroupMapsByGroupName("acme", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
        assertEquals(1, eDB.getExternalGroupMapsByGroupName("acme.dev", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    void cannotAddExternalGroupsThatDoNotExist() {
        Map<String, Map<String, List>> originMap = new HashMap<>();
        Map<String, List> externalGroupMap = new HashMap<>();
        externalGroupMap.put("cn=Engineering Department,ou=groups,dc=example,dc=com", Arrays.asList("acme", "acme.dev"));
        externalGroupMap.put("cn=HR,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=mgmt,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        originMap.put(OriginKeys.UAA, externalGroupMap);
        bootstrap.setExternalGroupMaps(originMap);
        bootstrap.afterPropertiesSet();

        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering Department,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());

        assertNull(eDB.getExternalGroupMapsByGroupName("acme1", OriginKeys.LDAP, IdentityZoneHolder.get().getId()));
        assertNull(eDB.getExternalGroupMapsByGroupName("acme1.dev", OriginKeys.LDAP, IdentityZoneHolder.get().getId()));
    }

    @Test
    void cannotAddExternalGroupsThatMapToNull() {
        Map<String, Map<String, List>> originMap = new HashMap<>();
        Map<String, List> externalGroupMap = new HashMap<>();
        externalGroupMap.put("cn=Engineering Department,ou=groups,dc=example,dc=com", null);
        originMap.put(OriginKeys.LDAP, externalGroupMap);
        bootstrap.setExternalGroupMaps(originMap);
        bootstrap.afterPropertiesSet();

        assertEquals(0, eDB.getExternalGroupMapsByExternalGroup("cn=Engineering Department,ou=groups,dc=example,dc=com", OriginKeys.LDAP, IdentityZoneHolder.get().getId()).size());
    }

    @Test
    void cannotAddOriginMapToNull() {
        Map<String, Map<String, List>> originMap = new HashMap<>();
        originMap.put(OriginKeys.LDAP, null);
        bootstrap.setExternalGroupMaps(originMap);
        bootstrap.afterPropertiesSet();
    }
}
