package org.cloudfoundry.identity.uaa.scim.groups;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.core.ScimResourceNotFoundException;
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
import org.springframework.util.StringUtils;

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

	private int existingGroupCount = -1;

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		dao = new JdbcScimGroupProvisioning(template);

		addGroup("g1", "uaa.user");
		addGroup("g2", "uaa.admin");
		addGroup("g3", "openid");

		validateGroupCount(3);
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "groups");
		validateGroupCount(0);

		TestUtils.deleteFrom(dataSource, "group_membership");
		assertEquals(0, template.queryForInt("select count(*) from group_membership"));
	}

	private void validateGroupCount(int expected) {
		existingGroupCount = template.queryForInt("select count(id) from groups");
		assertEquals(expected, existingGroupCount);
	}

	private void validateGroup(ScimGroup group, String name) {
		assertNotNull(group);
		assertNotNull(group.getId());
		assertNotNull(group.getDisplayName());
		if (StringUtils.hasText(name)) {
			assertEquals(name, group.getDisplayName());
		}
	}

	@Test
	public void canRetrieveGroups() throws Exception {
		List<ScimGroup> groups = dao.retrieveGroups();
		logger.debug(groups);
		assertEquals(3, groups.size());
		for (ScimGroup g : groups) {
			validateGroup(g, null);
		}
	}

	@Test
	public void canRetrieveGroupsWithFilter() throws Exception {
		assertEquals(1, dao.retrieveGroups("displayName eq 'uaa.user'").size());
		assertEquals(3, dao.retrieveGroups("displayName pr").size());
		assertEquals(1, dao.retrieveGroups("displayName eq \"openid\"").size());
		assertEquals(1, dao.retrieveGroups("DISPLAYNAMe eq 'uaa.admin'").size());
		assertEquals(1, dao.retrieveGroups("displayName EQ 'openid'").size());
		assertEquals(1, dao.retrieveGroups("displayName eq 'Openid'").size());
		assertEquals(1, dao.retrieveGroups("displayName co 'user'").size());
		assertEquals(3, dao.retrieveGroups("id sw 'g'").size());
		assertEquals(3, dao.retrieveGroups("displayName gt 'oauth'").size());
		assertEquals(0, dao.retrieveGroups("displayName lt 'oauth'").size());
		assertEquals(1, dao.retrieveGroups("displayName eq 'openid' and meta.version eq 0").size());
		assertEquals(3, dao.retrieveGroups("meta.created gt '1970-01-01T00:00:00.000Z'").size());
		assertEquals(3, dao.retrieveGroups("displayName pr and id co 'g'").size());
		assertEquals(2, dao.retrieveGroups("displayName eq 'openid' or displayName co '.user'").size());
		assertEquals(3, dao.retrieveGroups("displayName eq 'foo' or id sw 'g'").size());
	}

	@Test
	public void canRetrieveGroupsWithFilterAndSortBy() {
		assertEquals(3, dao.retrieveGroups("displayName pr", "id", true).size());
		assertEquals(1, dao.retrieveGroups("id co '2'", "displayName", false).size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveGroupsWithIllegalQuotesFilter() {
		assertEquals(1, dao.retrieveGroups("displayName eq 'bar").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveGroupsWithMissingQuotesFilter() {
		assertEquals(0, dao.retrieveGroups("displayName eq bar").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveGroupsWithInvalidFieldsFilter() {
		assertEquals(1, dao.retrieveGroups("name eq 'openid'").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveGroupsWithWrongFilter() {
		assertEquals(0, dao.retrieveGroups("displayName pr 'r'").size());
	}

	@Test
	public void canRetrieveGroup() throws Exception {
		ScimGroup group = dao.retrieveGroup("g1");
		validateGroup(group, "uaa.user");
	}

	@Test(expected = ScimResourceNotFoundException.class)
	public void cannotRetrieveNonExistentGroup() {
		dao.retrieveGroup("invalidgroup");
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
		validateGroup(g, "test.1");
	}

	@Test
	public void canUpdateGroup() throws Exception {
		ScimGroup g = dao.retrieveGroup("g1");
		logger.debug(g);
		assertEquals("uaa.user", g.getDisplayName());

		ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER);
		ScimGroupMember m2 = new ScimGroupMember("g2", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN);
		g.setMembers(Arrays.asList(m1, m2));
		g.setDisplayName("uaa.none");

		g = dao.updateGroup("g1", g);

		g = dao.retrieveGroup("g1");
		validateGroup(g, "uaa.none");
	}

	@Test
	public void canRemoveGroup() throws Exception {
		dao.removeGroup("g1", 0);
		validateGroupCount(2);
	}

	private void addGroup(String id, String name) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addGroupSqlFormat, id, name));
	}
}
