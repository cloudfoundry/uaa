package org.cloudfoundry.identity.uaa.authorization.external;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.authorization.LdapGroupMappingAuthorizationManager;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.LdapAuthority;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class LdapGroupMappingAuthorizationManagerTests {

    private JdbcScimGroupProvisioning gDB;
    private ScimGroupExternalMembershipManager eDB;
    private LdapGroupMappingAuthorizationManager manager;
    private ScimExternalGroupBootstrap bootstrap;
    private Set<? extends GrantedAuthority> nonLdapGroups;
    private Set<? extends GrantedAuthority> ldapGroups;

    private LdapAuthority la1 = new LdapAuthority("engineering", "cn=Engineering,ou=groups,dc=example,dc=com");
    private LdapAuthority la2 = new LdapAuthority("HR", "cn=HR,ou=groups,dc=example,dc=com");
    private LdapAuthority la3 = new LdapAuthority("mgmt", "cn=mgmt,ou=groups,dc=example,dc=com");

    private SimpleGrantedAuthority sa1 = new SimpleGrantedAuthority("acme");
    private SimpleGrantedAuthority sa2 = new SimpleGrantedAuthority("acme.dev");
    private SimpleGrantedAuthority sa3 = new SimpleGrantedAuthority("acme.notmapped");

    @BeforeEach
    void initLdapGroupMappingAuthorizationManagerTests(
            @Autowired JdbcTemplate jdbcTemplate,
            @Autowired LimitSqlAdapter limitSqlAdapter,
            @Autowired NamedParameterJdbcTemplate namedJdbcTemplate
    ) throws SQLException {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter);
        DbUtils dbUtils = new DbUtils();
        gDB = new JdbcScimGroupProvisioning(namedJdbcTemplate, pagingListFactory, dbUtils);
        eDB = new JdbcScimGroupExternalMembershipManager(jdbcTemplate, dbUtils);
        ((JdbcScimGroupExternalMembershipManager) eDB).setScimGroupProvisioning(gDB);
        assertThat(gDB.retrieveAll(IdentityZoneHolder.get().getId())).isEmpty();

        gDB.create(new ScimGroup(null, "acme", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());
        gDB.create(new ScimGroup(null, "acme.dev", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());

        bootstrap = new ScimExternalGroupBootstrap(gDB, eDB, new IdentityZoneManagerImpl());

        manager = new LdapGroupMappingAuthorizationManager();
        manager.setScimGroupProvisioning(gDB);
        manager.setExternalMembershipManager(eDB);

        Map<String, Map<String, List>> originMap = new HashMap<>();
        Map<String, List> externalGroupMap = new HashMap<>();
        externalGroupMap.put("cn=HR,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=mgmt,ou=groups,dc=example,dc=com", Collections.singletonList("acme"));
        externalGroupMap.put("cn=Engineering,ou=groups,dc=example,dc=com", Collections.singletonList("acme.dev"));
        originMap.put(OriginKeys.LDAP, externalGroupMap);
        bootstrap.setExternalGroupMaps(originMap);
        bootstrap.afterPropertiesSet();

        ldapGroups = new HashSet<>(Arrays.asList(new LdapAuthority[]{la1, la2, la3}));
        nonLdapGroups = new HashSet<>(Arrays.asList(new SimpleGrantedAuthority[]{sa1, sa2, sa3}));
    }

    @Test
    void allLdapGroups() {
        Set<? extends GrantedAuthority> result = manager.findScopesFromAuthorities(ldapGroups);
        String[] list = getAuthorities(Arrays.asList(sa1, sa2));
        assertThat(list).containsExactlyInAnyOrder(getAuthorities(result));
    }

    @Test
    void allNonLdapGroups() {
        Set<? extends GrantedAuthority> result = manager.findScopesFromAuthorities(nonLdapGroups);
        String[] list = getAuthorities(Arrays.asList(sa1, sa2, sa3));
        assertThat(list).containsExactlyInAnyOrder(getAuthorities(result));
    }

    @Test
    void mixedGroups() {
        Set<GrantedAuthority> mixed = new HashSet<>();
        mixed.add(sa1);
        mixed.add(sa3);
        mixed.add(la1);
        Set<? extends GrantedAuthority> result = manager.findScopesFromAuthorities(nonLdapGroups);
        String[] list = getAuthorities(Arrays.asList(sa1, sa2, sa3));
        assertThat(list).containsExactlyInAnyOrder(getAuthorities(result));
    }

    private static String[] getAuthorities(Collection<? extends GrantedAuthority> authorities) {
        String[] result = new String[authorities != null ? authorities.size() : 0];
        if (result.length > 0) {
            int index = 0;
            for (GrantedAuthority a : authorities) {
                result[index++] = a.getAuthority();
            }
        }
        return result;
    }
}
