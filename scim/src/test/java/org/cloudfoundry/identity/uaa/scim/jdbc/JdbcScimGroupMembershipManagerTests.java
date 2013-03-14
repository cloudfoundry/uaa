package org.cloudfoundry.identity.uaa.scim.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.scim.validate.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
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

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb", "test,mysql"})
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
		dao.setDefaultUserGroups(Collections.singleton("uaa.user"));

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
		Set<ScimGroup> directGroups = dao.getGroupsWithMember(id, false);
		assertNotNull(directGroups);
		Set<ScimGroup> indirectGroups = dao.getGroupsWithMember(id, true);
		indirectGroups.removeAll(directGroups);
		assertNotNull(indirectGroups);

		Set<String> expectedAuthorities = Collections.<String> emptySet();
		if (gNm != null) {
			expectedAuthorities = new HashSet<String>(Arrays.asList(gNm));
		}
		expectedAuthorities.add("uaa.user");

		assertEquals(expectedAuthorities.size(), directGroups.size() + indirectGroups.size());
		for (ScimGroup group : directGroups) {
			assertTrue(expectedAuthorities.contains(group.getDisplayName()));
		}
		for (ScimGroup group : indirectGroups) {
			assertTrue(expectedAuthorities.contains(group.getDisplayName()+".i"));
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
	public void canGetGroupsForMember() {
		addMember("g1", "m3", "USER", "READER");
		addMember("g1", "g2", "GROUP", "READER");
		addMember("g3", "m2", "USER", "READER,WRITER");
		addMember("g2", "m3", "USER", "READER");

		Set<ScimGroup> groups = dao.getGroupsWithMember("g2", false);
		assertNotNull(groups);
		assertEquals(1, groups.size());

		groups = dao.getGroupsWithMember("m3", true);
		assertNotNull(groups);
		assertEquals(3, groups.size());
	}

	@Test
	public void canGetGroupsForMemberEvenWhenCycleExistsInGroupHierarchy() {
		addMember("g1", "m3", "USER", "READER");
		addMember("g1", "g2", "GROUP", "READER");
		addMember("g2", "g3", "GROUP", "READER");
		addMember("g3", "g1", "GROUP", "READER");

		Set<ScimGroup> groups = dao.getGroupsWithMember("m3", true);
		assertNotNull(groups);
		assertEquals(4, groups.size());
	}

	@Test
	public void canAddMember() throws Exception {
		validateCount(0);
		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, null);
		ScimGroupMember m2 = dao.addMember("g2", m1);
		validateCount(1);
		assertEquals(ScimGroupMember.Type.USER, m2.getType());
		assertEquals(ScimGroupMember.GROUP_MEMBER, m2.getRoles());
		assertEquals("m1", m2.getMemberId());
		validateUserGroups("m1", "test2");
	}

	@Test
	public void canAddNestedGroupMember() {
		addMember("g2", "m1", "USER", "READER");

		ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
		g2 = dao.addMember("g1", g2);
		assertEquals(ScimGroupMember.Type.GROUP, g2.getType());
		assertEquals(ScimGroupMember.GROUP_ADMIN, g2.getRoles());
		assertEquals("g2", g2.getMemberId());
		validateUserGroups("m1", "test1.i", "test2");
	}

	@Test (expected = InvalidScimResourceException.class)
	public void cannotNestGroupWithinItself() {
		ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
		dao.addMember("g2", g2);
	}

	@Test
	public void canGetMembers() throws Exception {
		addMember("g1", "m1", "USER", "READER");
		addMember("g1", "g2", "GROUP", "READER");
		addMember("g3", "m2", "USER", "READER,WRITER");

		List<ScimGroupMember> members = dao.getMembers("g1");
		assertNotNull(members);
		assertEquals(2, members.size());

		members = dao.getMembers("g2");
		assertNotNull(members);
		assertEquals(0, members.size());

	}

	@Test
	public void testBackwardsCompatibilityToMemberAuthorities() {
		addMember("g1", "m1", "USER", "READ");
		addMember("g1", "g2", "GROUP", "member");
		addMember("g1", "m2", "USER", "READER,write");

		List<ScimGroupMember> members = dao.getMembers("g1");
		assertNotNull(members);
		assertEquals(3, members.size());
		List<ScimGroupMember> readers = new ArrayList<ScimGroupMember>(), writers = new ArrayList<ScimGroupMember>();
		for (ScimGroupMember member : members) {
			if (member.getRoles().contains(ScimGroupMember.Role.READER)) {
				readers.add(member);
			}
			if (member.getRoles().contains(ScimGroupMember.Role.WRITER)) {
				writers.add(member);
			}
		}
		assertEquals(2, readers.size());
		assertEquals(1, writers.size());
	}

	@Test
	public void canGetDefaultGroupsUsingGetGroupsForMember() {
		Set<ScimGroup> groups = dao.getGroupsWithMember("m1", false);
		assertNotNull(groups);
		assertEquals(1, groups.size());
	}

	@Test
	public void canGetAdminMembers() {
		addMember("g1", "m3", "USER", "READER,WRITER");
		addMember("g1", "g2", "GROUP", "READER");

		assertEquals(1, dao.getMembers("g1", ScimGroupMember.Role.WRITER).size());
		assertTrue(dao.getMembers("g1", ScimGroupMember.Role.WRITER).contains(new ScimGroupMember("m3")));

		assertEquals(0, dao.getMembers("g2", ScimGroupMember.Role.WRITER).size());
	}

	@Test
	public void canGetMembersByAuthority() {
		addMember("g1", "m3", "USER", "READER,WRITER");
		addMember("g1", "g2", "GROUP", "READER,MEMBER");
		addMember("g2", "g3", "GROUP", "MEMBER");

		assertEquals(1, dao.getMembers("g1", ScimGroupMember.Role.MEMBER).size());
		assertEquals(2, dao.getMembers("g1", ScimGroupMember.Role.READER).size());
		assertEquals(1, dao.getMembers("g1", ScimGroupMember.Role.WRITER).size());

		assertEquals(1, dao.getMembers("g2", ScimGroupMember.Role.MEMBER).size());
		assertEquals(0, dao.getMembers("g2", ScimGroupMember.Role.WRITER).size());
	}

	@Test
	public void canGetMemberById() throws Exception {
		addMember("g3", "m2", "USER", "READER,WRITER");

		ScimGroupMember m = dao.getMemberById("g3", "m2");
		assertEquals(ScimGroupMember.Type.USER, m.getType());
		assertEquals(ScimGroupMember.GROUP_ADMIN, m.getRoles());
	}

	@Test
	public void canUpdateMember() throws Exception {
		addMember("g1", "m1", "USER", "READER");
		validateCount(1);
		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN);
		ScimGroupMember m2 = dao.updateMember("g1", m1);
		assertEquals(ScimGroupMember.GROUP_ADMIN, m2.getRoles());
		assertNotSame(m1, m2);

		validateCount(1);
		validateUserGroups("m1", "test1");
	}

	@Test
	public void canUpdateOrAddMembers() {
		dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER));
		dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER));
		dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN));
		validateCount(3);
		validateUserGroups("m1", "test1");
		validateUserGroups("m2", "test2", "test1.i");

		ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_ADMIN);
		ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER);
		List<ScimGroupMember> members = dao.updateOrAddMembers("g1", Arrays.asList(g2, m3));

		validateCount(3);
		assertEquals(2, members.size());
		assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, null)));
		assertTrue(members.contains(new ScimGroupMember("m3", ScimGroupMember.Type.USER, null)));
		assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER, null)));
		validateUserGroups("m3", "test1");
		validateUserGroups("m2", "test2", "test1.i");
		validateUserGroups("m1");
	}

	@Test
	public void canRemoveMemberById() throws Exception {
		addMember("g1", "m1", "USER", "READER");
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
		dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER));
		dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER));
		dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN));
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
		dao.addMember("g1", new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_MEMBER));
		dao.addMember("g1", new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroupMember.GROUP_MEMBER));
		dao.addMember("g2", new ScimGroupMember("m2", ScimGroupMember.Type.USER, ScimGroupMember.GROUP_ADMIN));
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
