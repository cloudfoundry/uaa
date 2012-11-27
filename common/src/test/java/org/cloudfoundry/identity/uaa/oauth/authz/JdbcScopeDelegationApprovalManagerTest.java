package org.cloudfoundry.identity.uaa.oauth.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

import java.sql.Timestamp;
import java.util.Date;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScopeDelegationApprovalManagerTest {
	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScopeDelegationApprovalManager dao;

	private static final String addApprovalSqlFormat = "insert into authz_approvals (user_id, client_id, scope, expires_at) values ('%s','%s','%s','%s')";

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		dao = new JdbcScopeDelegationApprovalManager(template);

		addApproval("u1", "c1", "uaa.user", 6000);
		addApproval("u1", "c2", "uaa.admin", 12000);
		addApproval("u2", "c1", "openid", 6000);
	}

	private void addApproval(String userId, String clientId, String scope, long expiresIn) {
		template.execute(String.format(addApprovalSqlFormat, userId, clientId, scope, new Timestamp(new Date().getTime() + expiresIn)));
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "authz_approvals");
		assertEquals(0, template.queryForInt("select count(*) from authz_approvals"));
	}

	@Test
	public void canGetApprovals() {
		Set<ScopeDelegationApproval> app = dao.getApprovals("user_id pr");
		assertNotNull(app);
		assertEquals(3, app.size());
	}

}
