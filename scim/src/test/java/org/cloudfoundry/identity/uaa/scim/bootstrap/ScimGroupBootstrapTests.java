package org.cloudfoundry.identity.uaa.scim.bootstrap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
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
public class ScimGroupBootstrapTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimGroupProvisioning gDB;

	private JdbcScimUserProvisioning uDB;

	private JdbcScimGroupMembershipManager mDB;

	private ScimGroupBootstrap bootstrap;

	@Before
	public void setup() {
		template = new JdbcTemplate(dataSource);
		gDB = new JdbcScimGroupProvisioning(template);
		uDB = new JdbcScimUserProvisioning(template);
		uDB.setPasswordValidator(new NullPasswordValidator());
		mDB = new JdbcScimGroupMembershipManager(template);
		mDB.setScimGroupProvisioning(gDB);
		mDB.setScimUserProvisioning(uDB);

		uDB.createUser(TestUtils.scimUserInstance("dev1"), "test");
		uDB.createUser(TestUtils.scimUserInstance("dev2"), "test");
		uDB.createUser(TestUtils.scimUserInstance("dev3"), "test");
		uDB.createUser(TestUtils.scimUserInstance("qa1"), "test");
		uDB.createUser(TestUtils.scimUserInstance("qa2"), "test");
		uDB.createUser(TestUtils.scimUserInstance("mgr1"), "test");
		uDB.createUser(TestUtils.scimUserInstance("hr1"), "test");

		assertEquals(7, uDB.retrieveAll().size());
		assertEquals(0, gDB.retrieveAll().size());

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
		assertEquals(5, gDB.retrieveAll().size());
		assertNotNull(bootstrap.getGroup("org1.dev"));
		assertNotNull(bootstrap.getGroup("org1.qa"));
		assertNotNull(bootstrap.getGroup("org1.engg"));
		assertNotNull(bootstrap.getGroup("org1.mgr"));
		assertNotNull(bootstrap.getGroup("org1.hr"));
	}

	@Test
	public void testNullGroups() throws Exception {
		bootstrap.setGroups(null);
		bootstrap.afterPropertiesSet();
		assertEquals(0, gDB.retrieveAll().size());
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

		assertEquals(5, gDB.retrieveAll().size());
		assertEquals(7, uDB.retrieveAll().size());
		assertEquals(2, bootstrap.getGroup("org1.qa").getMembers().size());
		assertEquals(1, bootstrap.getGroup("org1.hr").getMembers().size());
		assertEquals(3, bootstrap.getGroup("org1.engg").getMembers().size());
		assertEquals(2, mDB.getMembers(bootstrap.getGroup("org1.dev").getId(), ScimGroupMember.Role.WRITER).size());
	}
}
