package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.oauth.authz.JdbcApprovalsManager;
import org.cloudfoundry.identity.uaa.oauth.authz.Approval;
import org.cloudfoundry.identity.uaa.oauth.authz.ApprovalsManager;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class UserManagedAuthzApprovalHandlerTests {
	
	private UserManagedAuthzApprovalHandler handler = new UserManagedAuthzApprovalHandler();

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private ApprovalsManager approvalManager = null;

	@Before
	public void setup()
	{
		template = new JdbcTemplate(dataSource);
		approvalManager = new JdbcApprovalsManager(template);
		handler.setApprovalsManager(approvalManager);
	}

	@Test
	public void testNoScopeApproval() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest(new HashMap<String, String>());
		request.setApproved(true);
		//The request is approved but does not request any scopes. The user has also not approved any scopes. Approved.
		assertTrue(handler.isApproved(request , new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testNoPreviouslyApprovedScopes() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>(Arrays.asList("cloud_controller.read", "cloud_controller.write")));
		request.setApproved(false);
		//The request needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertFalse(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testAuthzApprovedButNoPreviouslyApprovedScopes() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>(Arrays.asList("cloud_controller.read", "cloud_controller.write")));
		request.setApproved(true);
		//The request needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertTrue(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testNoRequestedScopesButSomeApprovedScopes() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>());
		request.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);

		long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
		Date nextWeek = new Date(theFuture);
		
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.read", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.write", nextWeek));

		//The request is not approved and needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertTrue(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}

	@Test
	public void testRequestedScopesDontMatchApprovalsAtAll() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>(Arrays.asList("openid")));
		request.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);

		long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
		Date nextWeek = new Date(theFuture);
		
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.read", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.write", nextWeek));

		//The request is approved but needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertFalse(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testOnlySomeRequestedScopeMatchesApproval() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>(Arrays.asList("openid", "cloud_controller.read")));
		request.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);

		long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
		Date nextWeek = new Date(theFuture);
		
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.read", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.write", nextWeek));

		//The request is approved but needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertFalse(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testRequestedScopesMatchApprovalButAdditionalScopesRequested() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", 
				new HashSet<String>(Arrays.asList("openid", "cloud_controller.read", "cloud_controller.write")));
		request.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);

		long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
		Date nextWeek = new Date(theFuture);
		
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.read", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.write", nextWeek));

		//The request is approved but needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertFalse(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testRequestedScopesMatchApproval() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>(Arrays.asList("openid", "cloud_controller.read", "cloud_controller.write")));
		request.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);

		long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
		Date nextWeek = new Date(theFuture);
		
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "openid", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.read", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.write", nextWeek));

		//The request is approved but needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertTrue(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@Test
	public void testSomeRequestedScopesMatchApproval() {
		DefaultAuthorizationRequest request = new DefaultAuthorizationRequest("foo", new HashSet<String>(Arrays.asList("openid")));
		request.setApproved(false);
		TestAuthentication userAuthentication = new TestAuthentication("marissa", true);

		long theFuture = System.currentTimeMillis() + (86400 * 7 * 1000);
		Date nextWeek = new Date(theFuture);
		
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "openid", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.read", nextWeek));
		approvalManager.addApproval(new Approval(userAuthentication.getPrincipal(), "foo", "cloud_controller.write", nextWeek));

		//The request is approved but needs user approval for scopes. The user has also not approved any scopes prior to this request. Not approved.
		assertTrue(handler.isApproved(request, new TestAuthentication("marissa", true)));
	}
	
	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "authz_approvals");
		assertEquals(0, template.queryForInt("select count(*) from authz_approvals"));
	}

	@SuppressWarnings("serial")
	protected static class TestAuthentication extends AbstractAuthenticationToken {
		private String principal;
		private String name;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
			this.name = name;
		}

		public Object getCredentials() {
			return null;
		}

		public String getPrincipal() {
			return this.principal;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}
		
	}

}
