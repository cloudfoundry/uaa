package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
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

import javax.sql.DataSource;

import java.util.*;

import static org.junit.Assert.*;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScimGroupMembershipManagerTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimGroupProvisioning gdao;

	private JdbcScimUserProvisioning udao;

	private JdbcScimGroupMembershipManager dao;

	private static final String addUserSqlFormat = "insert into users (id, username, password, email, givenName, familyName, phoneNumber, authorities) values ('%s','%s','%s','%s','%s','%s','%s', '%s')";

	private static final String addGroupSqlFormat = "insert into groups (id, displayName) values ('%s','%s')";

	private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, authorities) values ('%s', '%s', '%s', '%s')";

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		udao = new JdbcScimUserProvisioning(template);
		udao.setPasswordValidator(new NullPasswordValidator());
		gdao = new JdbcScimGroupProvisioning(template);

		dao = new JdbcScimGroupMembershipManager(template);
		dao.setScimGroupProvisioning(gdao);
		dao.setScimUserProvisioning(udao);

		addGroup("g1", "test1");
		addGroup("g2", "test2");
		addGroup("g3", "test3");
		addUser("m1", "test");
		addUser("m2", "test");
		addUser("m3", "test");

		validateCount(0);
	}

	private void addMember(String gId, String mId, String mType, String authorities) {
		template.execute(String.format(addMemberSqlFormat, gId, mId, mType, authorities));
	}

	private void addGroup(String id, String name) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addGroupSqlFormat, id, name));
	}

	private void addUser(String id, String password) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addUserSqlFormat, id, id, password, id, id, id, id, ""));
	}

	private void validateCount(int expected) {
		int existingMemberCount = template.queryForInt("select count(*) from group_membership");
		assertEquals(expected, existingMemberCount);
	}

	private void validateUserGroups (String id, String... gNm) {
		ScimUser user = udao.retrieveUser(id);
		Set<String> expectedAuthorities = new HashSet<String>();
		expectedAuthorities.addAll(Arrays.asList(gNm));
		expectedAuthorities.add("uaa.user");
		assertNotNull(user.getGroups());
		logger.debug("user's groups: " + user.getGroups() + ", expecting: " + expectedAuthorities);
		assertEquals(expectedAuthorities.size(), user.getGroups().size());
		for (ScimUser.Group g : user.getGroups()) {
			if (g.getMembershipType() == ScimUser.Group.MembershipType.INDIRECT) {
				assertTrue(expectedAuthorities.contains(g.getDisplay()+".i"));
			} else {
				assertTrue(expectedAuthorities.contains(g.getDisplay()));
			}
		}
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "group_membership");
		TestUtils.deleteFrom(dataSource, "groups");
		TestUtils.deleteFrom(dataSource, "users");

		validateCount(0);
	}

	@Test
	public void canAddMember() throws Exception {
		validateCount(0);
		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
		ScimGroupMember m2 = dao.addMember("g2", m1);
		validateCount(1);
		assertEquals(ScimGroupMember.Type.USER, m2.getType());
		assertEquals(ScimGroup.GROUP_MEMBER, m2.getAuthorities());
		assertEquals("m1", m2.getMemberId());
		validateUserGroups("m1", "test2");
	}

	@Test
	public void canAddNestedGroupMember() {
		addMember("g2", "m1", "USER", "READ");

		ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroup.GROUP_ADMIN);
		g2 = dao.addMember("g1", g2);
		assertEquals(ScimGroupMember.Type.GROUP, g2.getType());
		assertEquals(ScimGroup.GROUP_ADMIN, g2.getAuthorities());
		assertEquals("g2", g2.getMemberId());
		validateUserGroups("m1", "test1.i", "test2");
	}

	@Test
	public void canGetMembers() throws Exception {
		addMember("g1", "m1", "USER", "READ");
		addMember("g1", "g2", "GROUP", "READ");
		addMember("g3", "m2", "USER", "READ,WRITE");

		List<ScimGroupMember> members = dao.getMembers("g1");
		assertNotNull(members);
		assertEquals(2, members.size());

		members = dao.getMembers("g2");
		assertNotNull(members);
		assertEquals(0, members.size());

	}

	@Test
	public void canGetGroupsForMember() {
		addMember("g1", "m3", "USER", "READ");
		addMember("g1", "g2", "GROUP", "READ");
		addMember("g3", "m2", "USER", "READ,WRITE");
		addMember("g2", "m3", "USER", "READ");

		Set<ScimGroup> groups = dao.getGroupsWithMember("g2", false);
		assertNotNull(groups);
		assertEquals(1, groups.size());

		groups = dao.getGroupsWithMember("m3", true);
		assertNotNull(groups);
		assertEquals(2, groups.size());
	}

	@Test
	public void canGetDefaultGroupsUsingGetGroupsForMember() {
		addGroup("uaa.user", "uaa.user");
		addGroup("uaa.admin", "uaa.admin");
		Set<ScimGroup> groups = dao.getGroupsWithMember("m1", false);
		assertNotNull(groups);
		assertEquals(1, groups.size());
	}

	@Test
	public void canGetEndUserMembersForGroup() {
		addMember("g1", "m1", "USER", "READ");
		addMember("g1", "g2", "GROUP", "READ");
		addMember("g2", "m2", "USER", "READ,WRITE");

		Set<ScimGroupMember> userMembers = dao.getEndUserMembers("g1", false);
		assertNotNull(userMembers);
		assertEquals(1, userMembers.size());

		userMembers = dao.getEndUserMembers("g1", true);
		assertNotNull(userMembers);
		assertEquals(2, userMembers.size());
	}

	@Test
	public void canGetAdminMembers() {
		addMember("g1", "m3", "USER", "READ,WRITE");
		addMember("g1", "g2", "GROUP", "READ");

		assertEquals(1, dao.getAdminMembers("g1").size());
		assertTrue(dao.getAdminMembers("g1").contains(new ScimGroupMember("m3")));

		assertEquals(0, dao.getAdminMembers("g2").size());
	}

	@Test
	public void canGetMemberById() throws Exception {
		addMember("g3", "m2", "USER", "READ,WRITE");

		ScimGroupMember m = dao.getMemberById("g3", "m2");
		assertEquals(ScimGroupMember.Type.USER, m.getType());
		assertEquals(ScimGroup.GROUP_ADMIN, m.getAuthorities());
	}

	@Test
	public void canUpdateMember() throws Exception {
		addMember("g1", "m1", "USER", "READ");
		validateCount(1);
		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN);
		ScimGroupMember m2 = dao.updateMember("g1", m1);
		assertEquals(ScimGroup.GROUP_ADMIN, m2.getAuthorities());
		assertNotSame(m1, m2);

		validateCount(1);
		validateUserGroups("m1", "test1");
	}

	@Test
	public void canUpdateOrAddMembers() {
		dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER));
		dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroup.GROUP_MEMBER));
		dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN));
		validateCount(3);
		validateUserGroups("m1", "test1");
		validateUserGroups("m2", "test2", "test1.i");

		ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroup.GROUP_ADMIN);
		ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER);
		List<ScimGroupMember> members = dao.updateOrAddMembers("g1", Arrays.asList(g2, m3));

		validateCount(3);
		assertEquals(2, members.size());
		assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, null)));
		assertTrue(members.contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER, null)));
		assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER, null)));
		validateUserGroups("m3", "test1");
		validateUserGroups("m2", "test2", "test1.i");
		validateUserGroups("m1", "uaa.user");
	}

	@Test
	public void canRemoveMemberById() throws Exception {
		addMember("g1", "m1", "USER", "READ");
		validateCount(1);

		dao.removeMemberById("g1", "m1");
		validateCount(0);
		try {
			dao.getMemberById("g1", "m1");
			fail("member should not exist");
		} catch (MemberNotFoundException ex) {

		}
	}

	@Test
	public void canRemoveNestedGroupMember() {
		dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER));
		dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroup.GROUP_MEMBER));
		dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN));
		validateCount(3);
		validateUserGroups("m1", "test1");
		validateUserGroups("m2", "test2", "test1.i");

		dao.removeMemberById("g1", "g2");
		try {
			dao.getMemberById("g1", "g2");
			fail("member should not exist");
		} catch (MemberNotFoundException ex) {	}
		validateCount(2);
		validateUserGroups("m1", "test1");
		validateUserGroups("m2", "test2");

	}

	@Test
	public void canRemoveAllMembers() {
		dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER));
		dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroup.GROUP_MEMBER));
		dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN));
		validateCount(3);
		validateUserGroups("m1", "test1");
		validateUserGroups("m2", "test2", "test1.i");

		dao.removeMembersByGroupId("g1");
		validateCount(1);
		try {
			dao.getMemberById("g1", "m1");
			fail("member should not exist");
		} catch (MemberNotFoundException ex) {	}
		validateUserGroups("m1");
		validateUserGroups("m2", "test2");

	}
}
