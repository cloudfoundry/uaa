package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.ZoneSeeder;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.servlet.View;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DefaultTestContext
@ExtendWith(ZoneSeederExtension.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties = {
        "groupMaxCount=20",
        "userMaxCount=5"
})
class ScimGroupEndpointsTests {

    @Autowired
    private JdbcScimGroupProvisioning jdbcScimGroupProvisioning;

    @Autowired
    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    @Autowired
    private JdbcScimGroupExternalMembershipManager jdbcScimGroupExternalMembershipManager;

    @Autowired
    private ScimGroupEndpoints scimGroupEndpoints;

    @Autowired
    private ScimUserEndpoints scimUserEndpoints;

    private List<String> groupIds;

    private List<String> userIds;

    private static final String SQL_INJECTION_FIELDS = "displayName,version,created,lastModified";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private IdentityZone identityZone;

    @Autowired
    private IdentityZoneManager identityZoneManager;

    @Autowired
    @Qualifier("exceptionToStatusMap")
    private Map<Class<? extends Exception>, HttpStatus> exceptionToStatusMap;

    @BeforeEach
    void setUp(final ZoneSeeder zoneSeeder) {
        zoneSeeder.withDefaults().afterSeeding(zs -> setUpAfterSeeding(zs.getIdentityZone()));
    }

    private void setUpAfterSeeding(final IdentityZone identityZone) throws Exception {
        this.identityZone = identityZone;
        identityZoneManager.setCurrentIdentityZone(this.identityZone);
        TestUtils.deleteFrom(jdbcTemplate, "users", "groups", "group_membership");
        this.identityZone.getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        jdbcScimGroupProvisioning.createOrGet(new ScimGroup(null, "uaa.user", identityZoneManager.getCurrentIdentityZoneId()), identityZoneManager.getCurrentIdentityZoneId());

        groupIds = new ArrayList<>();
        userIds = new ArrayList<>();
        groupIds.add(addGroup("uaa.resource",
                Arrays.asList(createMember(ScimGroupMember.Type.USER),
                        createMember(ScimGroupMember.Type.GROUP),
                        createMember(ScimGroupMember.Type.USER)))
        );
        groupIds.add(addGroup("uaa.admin", Collections.emptyList()));
        groupIds.add(addGroup("uaa.none",
                Arrays.asList(createMember(ScimGroupMember.Type.USER),
                        createMember(ScimGroupMember.Type.GROUP)))
        );

        ScimExternalGroupBootstrap externalGroupBootstrap = new ScimExternalGroupBootstrap(jdbcScimGroupProvisioning, jdbcScimGroupExternalMembershipManager);
        externalGroupBootstrap.setAddNonExistingGroups(true);

        Map<String, Map<String, List>> externalGroups = new HashMap<>();
        Map<String, List> externalToInternalMap = new HashMap<>();
        externalToInternalMap.put("cn=test_org,ou=people,o=springsource,o=org", Collections.singletonList("organizations.acme"));
        externalToInternalMap.put("cn=developers,ou=scopes,dc=test,dc=com", Collections.singletonList("internal.read"));
        externalToInternalMap.put("cn=operators,ou=scopes,dc=test,dc=com", Collections.singletonList("internal.write"));
        externalToInternalMap.put("cn=superusers,ou=scopes,dc=test,dc=com", Arrays.asList("internal.everything", "internal.superuser"));
        externalGroups.put(OriginKeys.LDAP, externalToInternalMap);
        externalGroups.put("other-ldap", externalToInternalMap);
        externalGroupBootstrap.setExternalGroupMaps(externalGroups);
        externalGroupBootstrap.afterPropertiesSet();
    }

    private String addGroup(String name, List<ScimGroupMember> m) {
        ScimGroup g = new ScimGroup(null, name, identityZoneManager.getCurrentIdentityZoneId());
        g = jdbcScimGroupProvisioning.create(g, identityZoneManager.getCurrentIdentityZoneId());
        for (ScimGroupMember member : m) {
            jdbcScimGroupMembershipManager.addMember(g.getId(), member, identityZoneManager.getCurrentIdentityZoneId());
        }
        return g.getId();
    }

    private ScimGroupMember createMember(ScimGroupMember.Type t) {
        String id = UUID.randomUUID().toString();
        if (t == ScimGroupMember.Type.USER) {
            id = scimUserEndpoints.createUser(TestUtils.scimUserInstance(id), new MockHttpServletRequest(), new MockHttpServletResponse()).getId();
            userIds.add(id);
        } else {
            id = jdbcScimGroupProvisioning.create(new ScimGroup(null, id, identityZoneManager.getCurrentIdentityZoneId()), identityZoneManager.getCurrentIdentityZoneId()).getId();
            groupIds.add(id);
        }
        return new ScimGroupMember(id, t);
    }

    private void deleteGroup(String name) {
        for (ScimGroup g : jdbcScimGroupProvisioning.query("displayName eq \"" + name + "\"", identityZoneManager.getCurrentIdentityZoneId())) {
            jdbcScimGroupProvisioning.delete(g.getId(), g.getVersion(), identityZoneManager.getCurrentIdentityZoneId());
            jdbcScimGroupMembershipManager.removeMembersByGroupId(g.getId(), identityZoneManager.getCurrentIdentityZoneId());
        }
    }

    private void validateSearchResults(SearchResults<?> results, int expectedSize) {
        assertNotNull(results);
        assertNotNull(results.getResources());
        assertEquals(expectedSize, results.getResources().size());
    }

    private void validateGroup(ScimGroup g, String expectedName, int expectedMemberCount) {
        assertNotNull(g);
        assertNotNull(g.getId());
        assertEquals(expectedName, g.getDisplayName());
        assertNotNull(g.getMembers());
        assertEquals(expectedMemberCount, g.getMembers().size());
    }

    private void validateUserGroups(String id, String... gnm) {
        ScimUser user = scimUserEndpoints.getUser(id, new MockHttpServletResponse());
        Set<String> expectedAuthorities = new HashSet<>(Arrays.asList(gnm));
        expectedAuthorities.add("uaa.user");
        assertNotNull(user.getGroups());
        assertEquals(expectedAuthorities.size(), user.getGroups().size());
        for (ScimUser.Group g : user.getGroups()) {
            assertTrue(expectedAuthorities.contains(g.getDisplay()));
        }
    }

    @Test
    void listGroups() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName", "id pr", "created", "ascending", 1, 100), 11);
    }

    @Test
    void listGroupsWithAttributesWithoutMembersDoesNotQueryMembers() {
        ScimGroupMembershipManager memberManager = mock(ScimGroupMembershipManager.class);
        scimGroupEndpoints = new ScimGroupEndpoints(
                jdbcScimGroupProvisioning,
                memberManager,
                identityZoneManager,
                20,
                exceptionToStatusMap,
                jdbcScimGroupExternalMembershipManager);
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName", "id pr", "created", "ascending", 1, 100), 11);
        verify(memberManager, times(0)).getMembers(anyString(), any(Boolean.class), anyString());
    }

    @Test
    void listGroupsWithAttributesWithMembersDoesQueryMembers() {
        ScimGroupMembershipManager memberManager = mock(ScimGroupMembershipManager.class);
        when(memberManager.getMembers(anyString(), eq(false), eq("uaa"))).thenReturn(Collections.emptyList());
        scimGroupEndpoints = new ScimGroupEndpoints(
                jdbcScimGroupProvisioning,
                memberManager,
                identityZoneManager,
                20,
                exceptionToStatusMap,
                jdbcScimGroupExternalMembershipManager);
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName,members", "id pr", "created", "ascending", 1, 100), 11);
        verify(memberManager, atLeastOnce()).getMembers(anyString(), any(Boolean.class), anyString());
    }

    @Test
    void whenSettingAnInvalidGroupsMaxCount_ScimGroupsEndpointShouldThrowAnException() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> new ScimGroupEndpoints(null, null, null, 0, null, null),
                containsString("Invalid \"groupMaxCount\" value (got 0). Should be positive number."));
    }

    @Test
    void whenSettingANegativeValueGroupsMaxCount_ScimGroupsEndpointShouldThrowAnException() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> new ScimGroupEndpoints(null, null, null, -1, null, null),
                containsString("Invalid \"groupMaxCount\" value (got -1). Should be positive number."));
    }

    @Test
    void listGroups_Without_Description() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName,description", "id pr", "created", "ascending", 1, 100), 11);
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName,meta.lastModified", "id pr", "created", "ascending", 1, 100), 11);
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName,zoneId", "id pr", "created", "ascending", 1, 100), 11);
    }

    @Test
    void listExternalGroups() {
        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "", "", ""), 10);

        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "", OriginKeys.LDAP, ""), 5);
        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "", "", "cn=superusers,ou=scopes,dc=test,dc=com"), 4);
        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "", OriginKeys.LDAP, "cn=superusers,ou=scopes,dc=test,dc=com"), 2);
        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "", "you-wont-find-me", "cn=superusers,ou=scopes,dc=test,dc=com"), 0);

        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "externalGroup eq \"cn=superusers,ou=scopes,dc=test,dc=com\"", "", ""), 4);
        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "origin eq \"" + OriginKeys.LDAP + "\"", "", ""), 5);
        validateSearchResults(scimGroupEndpoints.getExternalGroups(1, 100, "externalGroup eq \"cn=superusers,ou=scopes,dc=test,dc=com\" and " + "origin eq \"" + OriginKeys.LDAP + "\"", "", ""), 2);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "dasda dasdas dasdas",
            "displayName eq \"test\""
    })
    void listExternalGroupsInvalidFilter(final String filter) {
        assertThrows(ScimException.class, () -> scimGroupEndpoints.getExternalGroups(1, 100, filter, null, null));
    }

    @Test
    void mapExternalGroup_truncatesLeadingAndTrailingSpaces_InExternalGroupName() {
        ScimGroupExternalMember member = getScimGroupExternalMember();
        assertEquals("external_group_id", member.getExternalGroup());
    }

    @Test
    void unmapExternalGroup_truncatesLeadingAndTrailingSpaces_InExternalGroupName() {
        ScimGroupExternalMember member = getScimGroupExternalMember();
        member = scimGroupEndpoints.unmapExternalGroup(member.getGroupId(), "  \nexternal_group_id\n", OriginKeys.LDAP);
        assertEquals("external_group_id", member.getExternalGroup());
    }

    @Test
    void unmapExternalGroupUsingName_truncatesLeadingAndTrailingSpaces_InExternalGroupName() {
        ScimGroupExternalMember member = getScimGroupExternalMember();
        member = scimGroupEndpoints.unmapExternalGroupUsingName(member.getDisplayName(), "  \nexternal_group_id\n");
        assertEquals("external_group_id", member.getExternalGroup());
    }

    private ScimGroupExternalMember getScimGroupExternalMember() {
        ScimGroupExternalMember member = new ScimGroupExternalMember(groupIds.get(0), "  external_group_id  ");
        member = scimGroupEndpoints.mapExternalGroup(member);
        return member;
    }

    @Test
    void findPageOfIds() {
        SearchResults<?> results = scimGroupEndpoints.listGroups("id", "id pr", null, "ascending", 1, 1);
        assertEquals(11, results.getTotalResults());
        assertEquals(1, results.getResources().size());
    }

    @Test
    void findMultiplePagesOfIds() {
        int pageSize = jdbcScimGroupProvisioning.getPageSize();
        jdbcScimGroupProvisioning.setPageSize(1);
        try {
            SearchResults<?> results = scimGroupEndpoints.listGroups("id", "id pr", null, "ascending", 1, 100);
            assertEquals(11, results.getTotalResults());
            assertEquals(11, results.getResources().size());
        } finally {
            jdbcScimGroupProvisioning.setPageSize(pageSize);
        }
    }

    @Test
    void listGroupsWithNameEqFilter() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"uaa.user\"", "created",
                "ascending", 1, 100), 1);
    }

    @Test
    void listGroupsWithNameCoFilter() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName", "displayName co \"admin\"", "created", "ascending",
                1, 100), 1);
    }

    @Test
    void listGroupsWithInvalidFilterFails() {
        assertThrowsWithMessageThat(ScimException.class,
                () -> scimGroupEndpoints.listGroups("id,displayName", "displayName cr \"admin\"", "created", "ascending", 1, 100),
                is("Invalid filter expression: [displayName cr &quot;admin&quot;]"));
    }

    @Test
    void listGroupsWithInvalidAttributes() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayNameee", "displayName co \"admin\"", "created", "ascending", 1, 100), 1);
    }

    @Test
    void listGroupsWithNullAttributes() {
        validateSearchResults(scimGroupEndpoints.listGroups(null, "displayName co \"admin\"", "created", "ascending", 1, 100), 1);
    }

    @Test
    void sqlInjectionAttackFailsCorrectly() {
        String sql = "displayName='something'; select " + SQL_INJECTION_FIELDS
                + " from groups where displayName='something'";
        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.listGroups("id,display", sql, "created", "ascending", 1, 100),
                "Invalid filter expression");
    }

    @Test
    void legacyTestListGroupsWithNameEqFilter() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName", "displayName eq 'uaa.user'", "created",
                "ascending", 1, 100), 1);
    }

    @Test
    void legacyTestListGroupsWithNameCoFilter() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayName", "displayName co 'admin'", "created", "ascending",
                1, 100), 1);
    }

    @Test
    void legacyTestListGroupsWithInvalidFilterFails() {
        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.listGroups("id,displayName", "displayName cr 'admin'", "created", "ascending", 1, 100),
                "Invalid filter expression");
    }

    @Test
    void legacyTestListGroupsWithInvalidAttributes() {
        validateSearchResults(scimGroupEndpoints.listGroups("id,displayNameee", "displayName co 'admin'", "created", "ascending", 1, 100), 1);
    }

    @Test
    void legacyTestListGroupsWithNullAttributes() {
        validateSearchResults(scimGroupEndpoints.listGroups(null, "displayName co 'admin'", "created", "ascending", 1, 100), 1);
    }

    @Test
    void getGroup() {
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        ScimGroup g = scimGroupEndpoints.getGroup(groupIds.get(groupIds.size() - 1), httpServletResponse);
        validateGroup(g, "uaa.none", 2);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @Test
    void getNonExistentGroupFails() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> scimGroupEndpoints.getGroup("wrongid", new MockHttpServletResponse()));
    }

    @Test
    void createGroup() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        ScimGroup g1 = scimGroupEndpoints.createGroup(g, httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));

        validateGroup(g1, "clients.read", 1);
        validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

        deleteGroup("clients.read");
    }

    @Test
    void createExistingGroupFails() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        try {
            scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
            fail("must have thrown exception");
        } catch (ScimResourceAlreadyExistsException ex) {
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 1);
        }

        deleteGroup("clients.read");
    }

    @Test
    void createGroupWithInvalidMemberFails() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(new ScimGroupMember("non-existent id", ScimGroupMember.Type.USER)));

        try {
            scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
            fail("must have thrown exception");
        } catch (InvalidScimResourceException ex) {
            // ensure that the group was not created
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 0);
        }
    }

    @Test
    void updateGroup() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

        g.setDisplayName("superadmin");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        ScimGroup g1 = scimGroupEndpoints.updateGroup(g, g.getId(), "*", httpServletResponse);
        assertEquals("\"1\"", httpServletResponse.getHeader("ETag"));

        validateGroup(g1, "superadmin", 1);
        validateUserGroups(g.getMembers().get(0).getMemberId(), "superadmin");
    }

    @Test
    void updateGroupQuotedEtag() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

        g.setDisplayName("superadmin");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        ScimGroup g1 = scimGroupEndpoints.updateGroup(g, g.getId(), "\"*\"", httpServletResponse);
        assertEquals("\"1\"", httpServletResponse.getHeader("ETag"));

        validateGroup(g1, "superadmin", 1);
        validateUserGroups(g.getMembers().get(0).getMemberId(), "superadmin");
    }

    @Test
    void updateGroupRemoveMembers() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

        g.setDisplayName("superadmin");
        g.setMembers(new ArrayList<>());
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        ScimGroup g1 = scimGroupEndpoints.updateGroup(g, g.getId(), "*", httpServletResponse);
        assertEquals("\"1\"", httpServletResponse.getHeader("ETag"));

        validateGroup(g1, "superadmin", 0);
    }

    @Test
    void updateGroupNullEtag() {
        final ScimGroup scimGroup = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        scimGroup.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        final ScimGroup createdScimGroup = scimGroupEndpoints.createGroup(scimGroup, new MockHttpServletResponse());
        validateUserGroups(scimGroup.getMembers().get(0).getMemberId(), "clients.read");

        scimGroup.setDisplayName("superadmin");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.updateGroup(createdScimGroup, createdScimGroup.getId(), null, httpServletResponse));
    }

    @Test
    void updateGroupNoEtag() {
        final ScimGroup scimGroup = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        scimGroup.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        final ScimGroup createdScimGroup = scimGroupEndpoints.createGroup(scimGroup, new MockHttpServletResponse());
        validateUserGroups(scimGroup.getMembers().get(0).getMemberId(), "clients.read");

        scimGroup.setDisplayName("superadmin");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.updateGroup(createdScimGroup, createdScimGroup.getId(), "", httpServletResponse));
    }

    @Test
    void updateGroupInvalidEtag() {
        final ScimGroup scimGroup = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        scimGroup.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        final ScimGroup createdScimGroup = scimGroupEndpoints.createGroup(scimGroup, new MockHttpServletResponse());
        validateUserGroups(scimGroup.getMembers().get(0).getMemberId(), "clients.read");

        scimGroup.setDisplayName("superadmin");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.updateGroup(createdScimGroup, createdScimGroup.getId(), "abc", httpServletResponse));
    }

    @Test
    void updateNonUniqueDisplayNameFails() {
        ScimGroup g1 = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g1.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g1 = scimGroupEndpoints.createGroup(g1, new MockHttpServletResponse());

        ScimGroup g2 = new ScimGroup(null, "clients.write", identityZoneManager.getCurrentIdentityZoneId());
        g2.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g2 = scimGroupEndpoints.createGroup(g2, new MockHttpServletResponse());

        g1.setDisplayName("clients.write");
        try {
            scimGroupEndpoints.updateGroup(g1, g1.getId(), "*", new MockHttpServletResponse());
            fail("must have thrown exception");
        } catch (InvalidScimResourceException ex) {
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.write\"", "id", "ASC", 1, 100), 1);
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 1);
        }

        deleteGroup("clients.read");
        deleteGroup("clients.write");
    }

    @Test
    void updateWithInvalidMemberFails() {
        ScimGroup g1 = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g1.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g1 = scimGroupEndpoints.createGroup(g1, new MockHttpServletResponse());

        g1.setMembers(
                Collections.singletonList(
                        new ScimGroupMember("non-existent id", ScimGroupMember.Type.USER)
                )
        );
        g1.setDisplayName("clients.write");

        try {
            scimGroupEndpoints.updateGroup(g1, g1.getId(), "*", new MockHttpServletResponse());
            fail("must have thrown exception");
        } catch (ScimException ex) {
            // ensure that displayName was not updated
            g1 = scimGroupEndpoints.getGroup(g1.getId(), new MockHttpServletResponse());
            validateGroup(g1, "clients.read", 0);
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.write\"", "id", "ASC", 1, 100), 0);
        }

        deleteGroup("clients.read");
    }

    @Test
    void updateInvalidVersionFails() {
        ScimGroup g1 = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g1.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g1 = scimGroupEndpoints.createGroup(g1, new MockHttpServletResponse());

        g1.setDisplayName("clients.write");

        try {
            scimGroupEndpoints.updateGroup(g1, g1.getId(), "version", new MockHttpServletResponse());
        } catch (ScimException ex) {
            assertTrue(ex.getMessage().contains("Invalid version"), "Wrong exception message");
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.write\"", "id", "ASC", 1, 100), 0);
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 1);
        }

        deleteGroup("clients.read");
    }

    @Test
    void updateGroupWithNullEtagFails() {
        ScimGroup g1 = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g1.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g1 = scimGroupEndpoints.createGroup(g1, new MockHttpServletResponse());

        g1.setDisplayName("clients.write");

        try {
            scimGroupEndpoints.updateGroup(g1, g1.getId(), null, new MockHttpServletResponse());
        } catch (ScimException ex) {
            assertTrue(ex.getMessage().contains("Missing If-Match"), "Wrong exception message");
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.write\"", "id", "ASC", 1, 100), 0);
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 1);
        }

        deleteGroup("clients.read");
    }

    @Test
    void updateWithQuotedVersionSucceeds() {
        ScimGroup g1 = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g1.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g1 = scimGroupEndpoints.createGroup(g1, new MockHttpServletResponse());

        g1.setDisplayName("clients.write");

        scimGroupEndpoints.updateGroup(g1, g1.getId(), "\"*", new MockHttpServletResponse());
        scimGroupEndpoints.updateGroup(g1, g1.getId(), "*\"", new MockHttpServletResponse());
        validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.write\"", "id", "ASC", 1, 100), 1);
        validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 0);

        deleteGroup("clients.write");
    }

    @Test
    void updateWrongVersionFails() {
        ScimGroup g1 = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g1.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g1 = scimGroupEndpoints.createGroup(g1, new MockHttpServletResponse());

        g1.setDisplayName("clients.write");

        try {
            scimGroupEndpoints.updateGroup(g1, g1.getId(), String.valueOf(g1.getVersion() + 23), new MockHttpServletResponse());
        } catch (ScimException ex) {
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.write\"", "id", "ASC", 1, 100), 0);
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 1);
        }

        deleteGroup("clients.read");
    }

    @Test
    void updateGroupWithNoMembers() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

        g.setDisplayName("someadmin");
        g.setMembers(null);
        ScimGroup g1 = scimGroupEndpoints.updateGroup(g, g.getId(), "*", new MockHttpServletResponse());
        validateGroup(g1, "someadmin", 0);

        deleteGroup("clients.read");
    }

    @Test
    void deleteGroup() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

        g = scimGroupEndpoints.deleteGroup(g.getId(), "*", new MockHttpServletResponse());
        try {
            scimGroupEndpoints.getGroup(g.getId(), new MockHttpServletResponse());
            fail("group should not exist");
        } catch (ScimResourceNotFoundException ignored) {
        }
        validateUserGroups(g.getMembers().get(0).getMemberId(), "uaa.user");
    }

    @Test
    void deleteGroupRemovesMembershipsInZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "test");
        zone.getConfig().getUserConfig().setDefaultGroups(emptyList());
        identityZoneManager.setCurrentIdentityZone(zone);

        ScimGroup group = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        ScimGroupMember member = createMember(ScimGroupMember.Type.GROUP);
        group.setMembers(Collections.singletonList(member));

        group = scimGroupEndpoints.createGroup(group, new MockHttpServletResponse());

        scimGroupEndpoints.deleteGroup(member.getMemberId(), "*", new MockHttpServletResponse());

        List<ScimGroupMember> members = scimGroupEndpoints.listGroupMemberships(group.getId(), true, "").getBody();
        assertEquals(0, members.size());
    }

    @Test
    void deleteWrongVersionFails() {
        ScimGroup g = new ScimGroup(null, "clients.read", identityZoneManager.getCurrentIdentityZoneId());
        g.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());

        try {
            scimGroupEndpoints.deleteGroup(g.getId(), String.valueOf(g.getVersion() + 3), new MockHttpServletResponse());
        } catch (ScimException ex) {
            validateSearchResults(scimGroupEndpoints.listGroups("id", "displayName eq \"clients.read\"", "id", "ASC", 1, 100), 1);
        }

        deleteGroup("clients.read");
    }

    @Test
    void deleteNonExistentGroupFails() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> scimGroupEndpoints.deleteGroup("some id", "*", new MockHttpServletResponse()));
    }

    @Test
    void exceptionHandler() {
        Map<Class<? extends Exception>, HttpStatus> map = new HashMap<>();
        map.put(IllegalArgumentException.class, HttpStatus.BAD_REQUEST);
        map.put(UnsupportedOperationException.class, HttpStatus.BAD_REQUEST);
        map.put(BadSqlGrammarException.class, HttpStatus.BAD_REQUEST);
        map.put(DataIntegrityViolationException.class, HttpStatus.BAD_REQUEST);
        map.put(HttpMessageConversionException.class, HttpStatus.BAD_REQUEST);
        map.put(HttpMediaTypeException.class, HttpStatus.BAD_REQUEST);

        scimGroupEndpoints = new ScimGroupEndpoints(
                jdbcScimGroupProvisioning,
                jdbcScimGroupMembershipManager,
                identityZoneManager,
                20,
                map,
                jdbcScimGroupExternalMembershipManager);


        MockHttpServletRequest request = new MockHttpServletRequest();
        validateView(scimGroupEndpoints.handleException(new ScimResourceNotFoundException(""), request), HttpStatus.NOT_FOUND);
        validateView(scimGroupEndpoints.handleException(new UnsupportedOperationException(""), request), HttpStatus.BAD_REQUEST);
        validateView(scimGroupEndpoints.handleException(new BadSqlGrammarException("", "", null), request),
                HttpStatus.BAD_REQUEST);
        validateView(scimGroupEndpoints.handleException(new IllegalArgumentException(""), request), HttpStatus.BAD_REQUEST);
        validateView(scimGroupEndpoints.handleException(new DataIntegrityViolationException(""), request),
                HttpStatus.BAD_REQUEST);
    }

    private void validateView(View view, HttpStatus status) {
        MockHttpServletResponse response = new MockHttpServletResponse();
        try {
            view.render(new HashMap<>(), new MockHttpServletRequest(), response);
            assertNotNull(response.getContentAsString());
        } catch (Exception e) {
            fail("view should render correct status and body");
        }
        assertEquals(status.value(), response.getStatus());
    }

    @Test
    void patch() {
        ScimGroup g1 = new ScimGroup(null, "name", identityZoneManager.getCurrentIdentityZoneId());
        g1.setDescription("description");

        g1 = jdbcScimGroupProvisioning.create(g1, identityZoneManager.getCurrentIdentityZoneId());

        ScimGroup patch = new ScimGroup("NewName");
        patch.setId(g1.getId());

        patch = scimGroupEndpoints.patchGroup(patch, patch.getId(), Integer.toString(g1.getVersion()), new MockHttpServletResponse());

        assertEquals("NewName", patch.getDisplayName());
        assertEquals(g1.getDescription(), patch.getDescription());
    }

    @Test
    void patchInvalidResourceFails() {
        ScimGroup g1 = new ScimGroup(null, "name", identityZoneManager.getCurrentIdentityZoneId());
        g1.setDescription("description");

        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.patchGroup(g1, "id", "0", new MockHttpServletResponse()));
    }

    @Test
    void patchAddMembers() {
        ScimGroup g1 = new ScimGroup(null, "name", identityZoneManager.getCurrentIdentityZoneId());
        g1.setDescription("description");

        g1 = jdbcScimGroupProvisioning.create(g1, identityZoneManager.getCurrentIdentityZoneId());

        ScimGroup patch = new ScimGroup();
        assertNull(g1.getMembers());
        assertNull(patch.getMembers());
        patch.setMembers(Collections.singletonList(createMember(ScimGroupMember.Type.USER)));
        assertEquals(1, patch.getMembers().size());

        patch = scimGroupEndpoints.patchGroup(patch, g1.getId(), "0", new MockHttpServletResponse());

        assertEquals(1, patch.getMembers().size());
        ScimGroupMember member = patch.getMembers().get(0);
        assertEquals(ScimGroupMember.Type.USER, member.getType());
    }

    @Test
    void patchIncorrectEtagFails() {
        ScimGroup scimGroup = new ScimGroup(null, "name", identityZoneManager.getCurrentIdentityZoneId());
        scimGroup.setDescription("description");

        final ScimGroup createdScimGroup = jdbcScimGroupProvisioning.create(scimGroup, identityZoneManager.getCurrentIdentityZoneId());

        ScimGroup patch = new ScimGroup("NewName");
        patch.setId(scimGroup.getId());

        assertThrows(ScimException.class,
                () -> scimGroupEndpoints.patchGroup(patch, patch.getId(), Integer.toString(createdScimGroup.getVersion() + 1), new MockHttpServletResponse()));
    }
}
