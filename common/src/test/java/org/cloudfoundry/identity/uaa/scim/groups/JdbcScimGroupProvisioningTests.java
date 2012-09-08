package org.cloudfoundry.identity.uaa.scim.groups;

import static org.junit.Assert.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.cloudfoundry.identity.uaa.scim.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
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
import java.util.Arrays;
import java.util.List;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScimGroupProvisioningTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimGroupProvisioning dao;

	private static final String addGroupSqlFormat = "insert into groups (id, displayName) values ('%s','%s')";

	private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, authorities) values ('%s', '%s', '%s', '%s')";

	private int existingGroupCount = -1;

	private int existingMemberCount = -1;

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		dao = new JdbcScimGroupProvisioning(template);

		addGroup("g1", "uaa.user");
		addGroup("g2", "uaa.admin");
		addGroup("g3", "openid");
		addMember("g1", "m1", "USER", "READ");
		addMember("g1", "g2", "GROUP", "READ");
		addMember("g3", "m3", "USER", "READ,WRITE");

		validateGroupCount(3);
		validateMemberCount("g1", 2);
		validateMemberCount("g2", 0);
		validateMemberCount("g3", 1);
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "groups");
		validateGroupCount(0);

		TestUtils.deleteFrom(dataSource, "group_membership");
		existingMemberCount = template.queryForInt("select count(*) from group_membership");
		assertEquals(0, existingMemberCount);
	}

	private void validateGroupCount(int expected) {
		existingGroupCount = template.queryForInt("select count(id) from groups");
		assertEquals(expected, existingGroupCount);
	}

	private void validateMemberCount(String gId, int expected) {
		existingMemberCount = template.queryForInt("select count(*) from group_membership where group_id='" + gId + "'");
		assertEquals(expected, existingMemberCount);
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testRetrieveGroupsWithFilter() throws Exception {
		dao.retrieveGroups("filter");
	}

	@Test(expected = UnsupportedOperationException.class)
	public void testRetrieveGroupsWithFilterAndSort() throws Exception {
		dao.retrieveGroups("filter", "created", true);
	}

	@Test
	public void canRetrieveGroups() throws Exception {
		List<ScimGroup> groups = dao.retrieveGroups();
		logger.debug(groups);
		assertEquals(3, groups.size());
	}

	@Test
	public void canRetrieveGroup() throws Exception {
		ScimGroup group = dao.retrieveGroup("g1");
		assertEquals("uaa.user", group.getDisplayName());
		assertEquals(2, group.getMembers().size());
	}

	@Test(expected = ScimResourceNotFoundException.class)
	public void cannotRetrieveNonExistentGroup() {
		dao.retrieveGroup("invalidgroup");
	}

	@Test
	public void canRetrieveGroupByName() {
		ScimGroup group = dao.retrieveGroupByName("openid");
		assertNotNull(group);
		assertNotNull(group.getId());
		assertNotNull(group.getMembers());
		assertEquals("openid", group.getDisplayName());
		assertEquals(1, group.getMembers().size());
	}

	@Test(expected = ScimResourceNotFoundException.class)
	public void cannotRetrieveNonExistentGroupByName() {
		dao.retrieveGroupByName("invalidgroup");
	}

	@Test
	public void canCreateGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "test.1");
		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER);
		ScimGroupMember m2 = new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN);
		g.setMembers(Arrays.asList(m1, m2));
		g = dao.createGroup(g);
		logger.debug(g);
		validateGroupCount(4);
		validateMemberCount(g.getId(), 2);
	}

	@Test
	public void canUpdateGroup() throws Exception {
		ScimGroup g = dao.retrieveGroup("g1");
		logger.debug(g);
		assertEquals(2, g.getMembers().size());
		assertEquals("uaa.user", g.getDisplayName());

		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER);
		ScimGroupMember m2 = new ScimGroupMember("g2", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN);
		g.setMembers(Arrays.asList(m1, m2));
		g.setDisplayName("uaa.none");

		enableUpdates();
		g = dao.updateGroup("g1", g);

		g = dao.retrieveGroup("g1");
		assertEquals("uaa.none", g.getDisplayName());
		assertEquals(2, g.getMembers().size());
		validateMemberCount("g1", 2);
	}

	private void enableUpdates() {
		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
		Mockito.when(context.isAdmin()).thenReturn(true);
		dao.setContext(context);
	}

	@Test
	public void canRemoveGroup() throws Exception {
		ScimGroup g = dao.removeGroup("g1", 0);
		validateGroupCount(2);
		validateMemberCount("g1", 0);
	}

	@Test
	public void canCheckIfUpdateAllowed() {
		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
		Mockito.when(context.isAdmin()).thenReturn(false);
		Mockito.when(context.isUser()).thenReturn(true);
		Mockito.when(context.getUserId()).thenReturn("m3");
		dao.setContext(context);

		dao.checkIfUpdateAllowed("g3");

		Mockito.when(context.isAdmin()).thenReturn(true);
		Mockito.when(context.getUserId()).thenReturn("m3");
		dao.setContext(context);

		dao.checkIfUpdateAllowed("g3");
		dao.checkIfUpdateAllowed("g2");
		dao.checkIfUpdateAllowed("invalidgroup");

		Mockito.when(context.getUserId()).thenReturn("m1");
		dao.setContext(context);

		dao.checkIfUpdateAllowed("g3");
		dao.checkIfUpdateAllowed("g2");
		dao.checkIfUpdateAllowed("invalidgroup");

	}

	@Test(expected = ScimException.class)
	public void canCheckIfUpdateAllowedFails() {
		SecurityContextAccessor context = Mockito.mock(DefaultSecurityContextAccessor.class);
		Mockito.when(context.isAdmin()).thenReturn(false);
		Mockito.when(context.getUserId()).thenReturn("m2");
		dao.setContext(context);

		dao.checkIfUpdateAllowed("g3");
	}

	private void addGroup(String id, String name) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addGroupSqlFormat, id, name));
	}

	private void addMember(String gId, String mId, String mType, String authorities) {
		template.execute(String.format(addMemberSqlFormat, gId, mId, mType, authorities));
	}
}
