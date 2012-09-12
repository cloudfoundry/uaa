package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import static org.junit.Assert.*;

import org.cloudfoundry.identity.uaa.user.UaaUser;
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
import java.util.Arrays;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ScimGroupBootstrapTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimGroupProvisioning gDB;

	private JdbcScimUserProvisioning uDB;

	private ScimGroupMembershipManager mDB;

	private ScimGroupBootstrap bootstrap;

	@Before
	public void setup() {
		template = new JdbcTemplate(dataSource);
		gDB = new JdbcScimGroupProvisioning(template);
		uDB = new JdbcScimUserProvisioning(template);
		uDB.setPasswordValidator(new NullPasswordValidator());
		mDB = new JdbcScimGroupMembershipManager(template);

		uDB.createUser(new ScimUser(null, "dev1"), "test");
		uDB.createUser(new ScimUser(null, "dev2"), "test");
		uDB.createUser(new ScimUser(null, "dev3"), "test");
		uDB.createUser(new ScimUser(null, "qa1"), "test");
		uDB.createUser(new ScimUser(null, "qa2"), "test");
		uDB.createUser(new ScimUser(null, "mgr1"), "test");
		uDB.createUser(new ScimUser(null, "hr1"), "test");

		assertEquals(7, uDB.retrieveUsers().size());
		assertEquals(0, gDB.retrieveGroups().size());

		bootstrap = new ScimGroupBootstrap(gDB, uDB, mDB);
	}

	@After
	public void cleanup() throws Exception {
		TestUtils.deleteFrom(dataSource, "users", "groups", "group_membership");
	}

	@Test
	public void canAddGroups() throws Exception {
		bootstrap.setGroups("org1.dev,org1.qa,org1.engg,org1.mgr,org1.hr");
		bootstrap.afterPropertiesSet();
		assertEquals(5, gDB.retrieveGroups().size());
		assertNotNull(gDB.retrieveGroupByName("org1.dev"));
		assertNotNull(gDB.retrieveGroupByName("org1.qa"));
		assertNotNull(gDB.retrieveGroupByName("org1.engg"));
		assertNotNull(gDB.retrieveGroupByName("org1.mgr"));
		assertNotNull(gDB.retrieveGroupByName("org1.hr"));
	}

	@Test
	public void canAddMembers() throws Exception {
		bootstrap.setGroupMembers(Arrays.asList(
				"org1.dev|dev1,dev2,dev3",
				"org1.dev|hr1,mgr1|write",
				"org1.qa|qa1,qa2,qa3",
				"org1.mgr|mgr1",
				"org1.hr|hr1",
				"org1.engg|org1.dev,org1.qa,org1.mgr"
		));
		bootstrap.afterPropertiesSet();

		assertEquals(5, gDB.retrieveGroups().size());
		assertEquals(7, uDB.retrieveUsers().size());
		assertEquals(2, gDB.retrieveGroupByName("org1.qa").getMembers().size());
		assertEquals(1, gDB.retrieveGroupByName("org1.hr").getMembers().size());
		assertEquals(3, gDB.retrieveGroupByName("org1.engg").getMembers().size());
		assertEquals(2, mDB.getAdminMembers(gDB.retrieveGroupByName("org1.dev").getId()).size());
	}
}
