package org.cloudfoundry.identity.uaa.oauth.authz;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.validate.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ApprovalsAdminEndpointsTests {
	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcApprovalsStore dao;

	private JdbcScimUserProvisioning userDao;

	private ScimUser marissa;

	private ApprovalsAdminEndpoints endpoints;

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		userDao = new JdbcScimUserProvisioning(template);
		userDao.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		userDao.setPasswordValidator(new NullPasswordValidator());

		marissa = new ScimUser(null, "marissa", "marissa", "koala");
		marissa.addEmail("marissa@test.com");
		marissa = userDao.createUser(marissa, "password");

		dao = new JdbcApprovalsStore(template);
		endpoints = new ApprovalsAdminEndpoints();
		endpoints.setApprovalsStore(dao);
		endpoints.setUsersManager(userDao);

		addApproval("marissa", "c1", "uaa.user", 6000);
		addApproval("marissa", "c1", "uaa.admin", 12000);
		addApproval("marissa", "c1", "openid", 6000);

		endpoints.setSecurityContextAccessor(mockSecurityContextAccessor(marissa.getId()));
	}

	private void addApproval(String userName, String clientId, String scope, long expiresIn) {
		dao.addApproval(new Approval(userName, clientId, scope, expiresIn));
	}

	private SecurityContextAccessor mockSecurityContextAccessor(String userName) {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getUserId()).thenReturn(userName);
		return sca;
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "authz_approvals");
		TestUtils.deleteFrom(dataSource, "users");
		assertEquals(0, template.queryForInt("select count(*) from authz_approvals"));
		assertEquals(0, template.queryForInt("select count(*) from users"));
	}

	@Test
	public void canGetApprovals() {
		assertEquals(3, endpoints.getApprovals("userName pr", 1, 100).size());
		assertEquals(2, endpoints.getApprovals("userName pr", 1, 2).size());
	}

	@Test
	public void canUpdateApprovals() {
		List<Approval> app = Arrays.asList(new Approval("marissa", "c1", "uaa.user", 2000),
														  new Approval("marissa", "c1", "dash.user", 2000));
		List<Approval> response = endpoints.updateApprovals(app);
		assertEquals(2, response.size());
		assertFalse(response.contains(new Approval("marissa", "c1", "openid", 0)));
		assertFalse(response.contains(new Approval("marissa", "c1", "uaa.admin", 0)));
	}

	@Test (expected = UaaException.class)
	public void userCannotUpdateApprovalsForAnotherUser() {
		ScimUser vidya = new ScimUser(null, "vidya", "vidya", "v");
		vidya.addEmail("vidya@test.com");
		vidya = userDao.createUser(vidya, "password");

		endpoints.setSecurityContextAccessor(mockSecurityContextAccessor(vidya.getId()));
		endpoints.updateApprovals(Arrays.asList(new Approval("marissa", "c1", "uaa.user", 2000)));
	}

	@Test
	public void canRevokeApprovals() {
		assertEquals(3, endpoints.getApprovals("userName pr", 1, 100).size());
		assertEquals("ok", endpoints.revokeApprovals().getStatus());
		assertEquals(0, endpoints.getApprovals("userName pr", 1, 100).size());
	}
}
