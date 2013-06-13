package org.cloudfoundry.identity.uaa.scim.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.rest.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
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
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb", "test,mysql", "test,oracle"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScimGroupExternalMembershipManagerTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	@Autowired
	private LimitSqlAdapter limitSqlAdapter;

	private JdbcScimGroupProvisioning gdao;

	private JdbcScimGroupExternalMembershipManager edao;

	private static final String addGroupSqlFormat = "insert into groups (id, displayName) values ('%s','%s')";

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(template, limitSqlAdapter);
		gdao = new JdbcScimGroupProvisioning(template, pagingListFactory);

		edao = new JdbcScimGroupExternalMembershipManager(template, pagingListFactory);
		edao.setScimGroupProvisioning(gdao);

		addGroup("g1", "test1");
		addGroup("g2", "test2");
		addGroup("g3", "test3");

		validateCount(0);
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "groups");
		TestUtils.deleteFrom(dataSource, "external_group_mapping");

		validateCount(0);
	}

	private void addGroup(String id, String name) {
		TestUtils.assertNoSuchUser(template, "id", id);
		template.execute(String.format(addGroupSqlFormat, id, name));
	}

	private void validateCount(int expected) {
		int existingMemberCount = template.queryForInt("select count(*) from external_group_mapping");
		assertEquals(expected, existingMemberCount);
	}

	@Test
	public void addExternalMappingToGroup() {
		ScimGroup group = gdao.retrieve("g1");
		assertNotNull(group);

		ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=engineering,ou=groups,dc=example,dc=com");
		assertEquals(member.getGroupId(), "g1");
		assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");

		List<ScimGroupExternalMember> externalMapping = edao.getExternalGroupMapsByGroupId("g1");

		assertEquals(externalMapping.size(), 1);
	}

	@Test(expected = MemberAlreadyExistsException.class)
	public void addExternalMappingToGroupThatAlreadyExists() {
		ScimGroup group = gdao.retrieve("g1");
		assertNotNull(group);

		ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=engineering,ou=groups,dc=example,dc=com");
		assertEquals(member.getGroupId(), "g1");
		assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");

		List<ScimGroupExternalMember> externalMapping = edao.getExternalGroupMapsByGroupId("g1");

		assertEquals(externalMapping.size(), 1);

		ScimGroupExternalMember dupMember = edao.mapExternalGroup("g1", "cn=engineering,ou=groups,dc=example,dc=com");
	}

	@Test
	public void addMultipleExternalMappingsToGroup() {
		ScimGroup group = gdao.retrieve("g1");
		assertNotNull(group);

		{
			ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=engineering,ou=groups,dc=example,dc=com");
			assertEquals(member.getGroupId(), "g1");
			assertEquals(member.getExternalGroup(), "cn=engineering,ou=groups,dc=example,dc=com");
		}

		{
			ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=hr,ou=groups,dc=example,dc=com");
			assertEquals(member.getGroupId(), "g1");
			assertEquals(member.getExternalGroup(), "cn=hr,ou=groups,dc=example,dc=com");
		}

		{
			ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=mgmt,ou=groups,dc=example,dc=com");
			assertEquals(member.getGroupId(), "g1");
			assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
		}

		List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g1");
		assertEquals(externalMappings.size(), 3);

		List<String> testGroups = new ArrayList<String>(Arrays.asList(new String[]{"cn=engineering,ou=groups,dc=example,dc=com",
																				  "cn=hr,ou=groups,dc=example,dc=com",
																				  "cn=mgmt,ou=groups,dc=example,dc=com"}));
		for (ScimGroupExternalMember member : externalMappings) {
			assertEquals(member.getGroupId(), "g1");
			assertNotNull(testGroups.remove(member.getExternalGroup()));
		}

		assertEquals(testGroups.size(), 0);
	}

	@Test
	public void addMultipleExternalMappingsToMultipleGroup() {
		{
			ScimGroup group = gdao.retrieve("g1");
			assertNotNull(group);

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=Engineering,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g1");
				assertEquals(member.getExternalGroup(), "cn=Engineering,ou=groups,dc=example,dc=com");
			}

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=HR,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g1");
				assertEquals(member.getExternalGroup(), "cn=HR,ou=groups,dc=example,dc=com");
			}

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g1", "cn=mgmt,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g1");
				assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
			}
			List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g1");
			assertEquals(externalMappings.size(), 3);
		}
		{
			ScimGroup group = gdao.retrieve("g2");
			assertNotNull(group);

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g2", "cn=Engineering,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g2");
				assertEquals(member.getExternalGroup(), "cn=Engineering,ou=groups,dc=example,dc=com");
			}

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g2", "cn=HR,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g2");
				assertEquals(member.getExternalGroup(), "cn=HR,ou=groups,dc=example,dc=com");
			}

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g2", "cn=mgmt,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g2");
				assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
			}
			List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g2");
			assertEquals(externalMappings.size(), 3);
		}
		{
			ScimGroup group = gdao.retrieve("g3");
			assertNotNull(group);

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g3", "cn=Engineering,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g3");
				assertEquals(member.getExternalGroup(), "cn=Engineering,ou=groups,dc=example,dc=com");
			}

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g3", "cn=HR,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g3");
				assertEquals(member.getExternalGroup(), "cn=HR,ou=groups,dc=example,dc=com");
			}

			{
				ScimGroupExternalMember member = edao.mapExternalGroup("g3", "cn=mgmt,ou=groups,dc=example,dc=com");
				assertEquals(member.getGroupId(), "g3");
				assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
			}
			List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByGroupId("g3");
			assertEquals(externalMappings.size(), 3);
		}

		List<String> testGroups = new ArrayList<String>(Arrays.asList(new String[]{"g1", "g2", "g3"}));

		{
			//LDAP groups are case preserving on fetch and case insensitive on search
			List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByExternalGroup("cn=engineering,ou=groups,dc=example,dc=com");
			for (ScimGroupExternalMember member : externalMappings) {
				assertEquals(member.getExternalGroup(), "cn=Engineering,ou=groups,dc=example,dc=com");
				assertNotNull(testGroups.remove(member.getGroupId()));
			}

			assertEquals(testGroups.size(), 0);
		}

		{
			//LDAP groups are case preserving on fetch and case insensitive on search
			List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByExternalGroup("cn=hr,ou=groups,dc=example,dc=com");
			for (ScimGroupExternalMember member : externalMappings) {
				assertEquals(member.getExternalGroup(), "cn=HR,ou=groups,dc=example,dc=com");
				assertNotNull(testGroups.remove(member.getGroupId()));
			}

			assertEquals(testGroups.size(), 0);

			List<ScimGroupExternalMember> externalMappings2 = edao.getExternalGroupMapsByExternalGroup("cn=HR,ou=groups,dc=example,dc=com");
			for (ScimGroupExternalMember member : externalMappings2) {
				assertEquals(member.getExternalGroup(), "cn=HR,ou=groups,dc=example,dc=com");
				assertNotNull(testGroups.remove(member.getGroupId()));
			}

			assertEquals(testGroups.size(), 0);
		}

		{
			//LDAP groups are case preserving on fetch and case insensitive on search
			List<ScimGroupExternalMember> externalMappings = edao.getExternalGroupMapsByExternalGroup("cn=mgmt,ou=groups,dc=example,dc=com");
			for (ScimGroupExternalMember member : externalMappings) {
				assertEquals(member.getExternalGroup(), "cn=mgmt,ou=groups,dc=example,dc=com");
				assertNotNull(testGroups.remove(member.getGroupId()));
			}

			assertEquals(testGroups.size(), 0);
		}
	}
}

