package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;

import static org.junit.Assert.*;

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.sql.DataSource;
import java.util.*;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ScimGroupEndpointsTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimGroupProvisioning dao;

	private JdbcScimUserProvisioning udao;

	private JdbcScimGroupMembershipManager mm;

	private ScimGroupEndpoints endpoints;

	private ScimUserEndpoints userEndpoints;

	private List<String> groupIds;

	@Before
	public void setup() {
		template = new JdbcTemplate(dataSource);
		dao = new JdbcScimGroupProvisioning(template);
		udao = new JdbcScimUserProvisioning(template);
		udao.setPasswordValidator(new NullPasswordValidator());
		mm = new JdbcScimGroupMembershipManager(template);
		mm.setScimGroupProvisioning(dao);
		mm.setScimUserProvisioning(udao);
		endpoints = new ScimGroupEndpoints(dao, mm);
		userEndpoints = new ScimUserEndpoints();
		userEndpoints.setScimUserProvisioning(udao);
		userEndpoints.setScimGroupMembershipManager(mm);

		groupIds = new ArrayList<String>();
		groupIds.add(addGroup("uaa.user", Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER),
															   createMember(ScimGroupMember.Type.GROUP, ScimGroup.GROUP_MEMBER),
															   createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)))
		);
		groupIds.add(addGroup("uaa.admin", Collections.<ScimGroupMember>emptyList()));
		groupIds.add(addGroup("uaa.none", Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER),
															   createMember(ScimGroupMember.Type.GROUP, ScimGroup.GROUP_ADMIN)))
		);

	}

	@After
	public void cleanup() throws Exception {
		TestUtils.deleteFrom(dataSource, "users");
		TestUtils.deleteFrom(dataSource, "groups");
		TestUtils.deleteFrom(dataSource, "group_membership");
	}

	private String addGroup(String name, List<ScimGroupMember> m) {
		ScimGroup g = new ScimGroup("", name);
		g = dao.createGroup(g);
		for (ScimGroupMember member : m) {
			mm.addMember(g.getId(), member);
		}
		return g.getId();
	}

	private ScimGroupMember createMember(ScimGroupMember.Type t, List<ScimGroup.Authority> a) {
		String id = UUID.randomUUID().toString();
		if (t == ScimGroupMember.Type.USER) {
			id = userEndpoints.createUser(TestUtils.scimUserInstance(id)).getId();
		} else {
			id = dao.createGroup(new ScimGroup("", id)).getId();
		}
		return new ScimGroupMember(id, t, a);
	}

	private void validateSearchResults (SearchResults<?> results, int expectedSize) {
		assertNotNull(results);
		assertNotNull(results.getResources());
		assertEquals(expectedSize, results.getResources().size());
	}

	private void validateGroup(ScimGroup g, String expectedName, int expectedMemberCount) {
		assertNotNull(g);
		assertNotNull(g.getId());
		assertNotNull(g.getVersion());
		assertEquals(expectedName, g.getDisplayName());
		assertNotNull(g.getMembers());
		assertEquals(expectedMemberCount, g.getMembers().size());
	}

	private void validateUserGroups (String id, String... gnm) {
		ScimUser user = userEndpoints.getUser(id);
		Set<String> expectedAuthorities = new HashSet<String>();
		expectedAuthorities.addAll(Arrays.asList(gnm));
		expectedAuthorities.add("uaa.user");
		assertNotNull(user.getGroups());
		logger.debug("user's groups: " + user.getGroups() + ", expecting: " + expectedAuthorities);
		assertEquals(expectedAuthorities.size(), user.getGroups().size());
		for (ScimUser.Group g : user.getGroups()) {
			assertTrue(expectedAuthorities.contains(g.getDisplay()));
		}
	}

	@Test
	public void testListGroups() throws Exception {
		validateSearchResults(endpoints.listGroups("id,displayName", "id pr", "created", "ascending", 1, 100), 5);
	}

	@Test
	public void testListGroupsWithNameEqFilter() {
		validateSearchResults(endpoints.listGroups("id,displayName", "displayName eq 'uaa.user'", "created", "ascending", 1, 100), 1);
	}

	@Test
	public void testListGroupsWithNameCoFilter() {
		validateSearchResults(endpoints.listGroups("id,displayName", "displayName co 'admin'", "created", "ascending", 1, 100), 1);
	}

	@Test
	public void testGetGroup() throws Exception {
		ScimGroup g = endpoints.getGroup(groupIds.get(0));
		validateGroup(g, "uaa.user", 3);
	}

	@Test
	public void testCreateGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		ScimGroup g1 = endpoints.createGroup(g);
		validateGroup(g1, "clients.read", 1);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");
	}

	@Test
	public void testUpdateGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g = endpoints.createGroup(g);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

		g.setDisplayName("superadmin");
		g.getMembers().get(0).setAuthorities(ScimGroup.GROUP_MEMBER);
		enableUpdates();
		ScimGroup g1 = endpoints.updateGroup(g, g.getId(), "*");

		validateGroup(g1, "superadmin", 1);
		assertEquals(ScimGroup.GROUP_MEMBER, g1.getMembers().get(0).getAuthorities());
		validateUserGroups(g.getMembers().get(0).getMemberId(), "superadmin");

	}

//	@Test
//	public void canCheckIfUpdateAllowed() {
//		ScimGroupMember m1 = createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER);
//		ScimGroupMember m2 = createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN);
//		String gId = addGroup("test", Arrays.asList(m1, m2));
//
//		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
//		Mockito.when(context.isAdmin()).thenReturn(false);
//		Mockito.when(context.isUser()).thenReturn(true);
//		Mockito.when(context.getUserId()).thenReturn(m2.getMemberId());
//		endpoints.setContext(context);
//
//		endpoints.checkIfUpdateAllowed(gId);
//
//		Mockito.when(context.isAdmin()).thenReturn(true);
//		Mockito.when(context.getUserId()).thenReturn(m1.getMemberId());
//		endpoints.setContext(context);
//
//		endpoints.checkIfUpdateAllowed(gId);
//		endpoints.checkIfUpdateAllowed("invalidgroup");
//
//		Mockito.when(context.getUserId()).thenReturn("invaliduser");
//		endpoints.setContext(context);
//
//		endpoints.checkIfUpdateAllowed(gId);
//		endpoints.checkIfUpdateAllowed("invalidgroup");
//
//	}
//
//	@Test(expected = ScimException.class)
//	public void canCheckIfUpdateAllowedFails() {
//		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
//		Mockito.when(context.isAdmin()).thenReturn(false);
//		Mockito.when(context.getUserId()).thenReturn("m2");
//		endpoints.setContext(context);
//
//		endpoints.checkIfUpdateAllowed("g3");
//	}

	private void enableUpdates() {
		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
		Mockito.when(context.isAdmin()).thenReturn(true);
		endpoints.setContext(context);
	}

	@Test
	public void testDeleteGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g = endpoints.createGroup(g);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

		g = endpoints.deleteGroup(g.getId(), "*");
		try {
			endpoints.getGroup(g.getId());
			fail("group should not exist");
		} catch (ScimResourceNotFoundException ex) { }
		logger.debug("deleted group: " + g);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "uaa.user");
	}
}
