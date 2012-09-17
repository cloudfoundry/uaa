package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.SearchResults;
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

	private ScimGroupEndpoints endpoints;

	private List<String> groupIds;

	@Before
	public void setup() {
		template = new JdbcTemplate(dataSource);
		dao = new JdbcScimGroupProvisioning(template);
		endpoints = new ScimGroupEndpoints(dao);

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
		TestUtils.deleteFrom(dataSource, "groups");
		TestUtils.deleteFrom(dataSource, "group_membership");
	}

	private String addGroup(String name, List<ScimGroupMember> m) {
		ScimGroup g = new ScimGroup("", name);
		g.setMembers(m);
		return dao.createGroup(g).getId();
	}

	private ScimGroupMember createMember(ScimGroupMember.Type t, List<ScimGroup.Authority> a) {
		String id = UUID.randomUUID().toString();
		return new ScimGroupMember(id, t, a);
	}

	private void validateSearchResults (Collection<Map<String, Object>> groups, String... names) {
		List<String> gnm = Arrays.asList(names);
		assertEquals(gnm.size(), groups.size());
		for (Map<String, Object> g : groups) {
			assertTrue(gnm.contains(g.get("displayName")));
			assertNotNull(g.get("id"));
		}
	}

	@Test
	public void testListGroups() throws Exception {
		SearchResults<Map<String, Object>> results = endpoints.listGroups("id,displayName", "id pr", "created", "ascending", 1, 100);
		assertNotNull(results);
		validateSearchResults(results.getResources(), "uaa.user", "uaa.admin", "uaa.none");
	}

	@Test
	public void testListGroupsWithNameEqFilter() {
		SearchResults<Map<String, Object>> results = endpoints.listGroups("id,displayName", "displayName eq 'uaa.user'", "created", "ascending", 1, 100);
		assertNotNull(results);
		validateSearchResults(results.getResources(), "uaa.user");
	}

	@Test
	public void testListGroupsWithNameCoFilter() {
		SearchResults<Map<String, Object>> results = endpoints.listGroups("id,displayName", "displayName co 'admin'", "created", "ascending", 1, 100);
		assertNotNull(results);
		validateSearchResults(results.getResources(), "uaa.admin");
	}

	@Test
	public void testGetGroup() throws Exception {
		ScimGroup g = endpoints.getGroup(groupIds.get(0));
		assertNotNull(g);
		assertNotNull(g.getVersion());
		assertEquals("uaa.user", g.getDisplayName());
		assertNotNull(g.getMembers());
		assertEquals(3, g.getMembers().size());
	}

	@Test
	public void testCreateGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN), createMember(ScimGroupMember.Type.GROUP, ScimGroup.GROUP_MEMBER)));
		ScimGroup g1 = endpoints.createGroup(g);
		assertNotNull(g1);
		assertNotNull(g1.getId());

		ScimGroup g2 = dao.retrieveGroup(g1.getId());
		assertEquals("clients.read", g2.getDisplayName());
		assertEquals(2, g2.getMembers().size());
		assertNotNull(g2.getVersion());

	}

	@Test
	public void testUpdateGroup() throws Exception {
		ScimGroup g = new ScimGroup(groupIds.get(1), "superadmin");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));

		enableUpdates();
		ScimGroup g1 = endpoints.updateGroup(g, g.getId(), "*");

		assertNotNull(g1);
		assertNotNull(g1.getVersion());
		assertEquals("superadmin", g1.getDisplayName());
		assertEquals(g.getId(), g1.getId());
		assertEquals(1, g1.getMembers().size());
	}

	private void enableUpdates() {
		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
		Mockito.when(context.isAdmin()).thenReturn(true);
		dao.setContext(context);
	}

	@Test
	public void testDeleteGroup() throws Exception {
		endpoints.deleteGroup(groupIds.get(1), "*");
		try {
			endpoints.getGroup(groupIds.get(1));
			fail("group should not exist");
		} catch (ScimResourceNotFoundException ex) {

		}
	}
}
