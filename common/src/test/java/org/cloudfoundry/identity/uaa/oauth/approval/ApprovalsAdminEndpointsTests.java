/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth.approval;

import static org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus.DENIED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.rest.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb", "test,mysql"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ApprovalsAdminEndpointsTests {
	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcApprovalStore dao;

	private UaaUserDatabase userDao = new MockUaaUserDatabase("FOO", "marissa", "marissa@test.com", "Marissa", "Bloggs");

	private UaaUser marissa;

	private ApprovalsAdminEndpoints endpoints;

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);
		marissa = userDao.retrieveUserByName("marissa");

		dao = new JdbcApprovalStore(template, new SimpleSearchQueryConverter());
		endpoints = new ApprovalsAdminEndpoints();
		endpoints.setApprovalStore(dao);
		endpoints.setUaaUserDatabase(userDao);
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		BaseClientDetails details = new BaseClientDetails("c1", "scim,clients", "read,write",
				"authorization_code, password, implicit, client_credentials", "update");
		details.addAdditionalInformation("autoapprove", "true");
		clientDetailsService.setClientDetailsStore(Collections
				.singletonMap("c1", details));
		endpoints.setClientDetailsService(clientDetailsService);

		endpoints.setSecurityContextAccessor(mockSecurityContextAccessor(marissa.getUsername()));
	}

	private void addApproval(String userName, String clientId, String scope, int expiresIn, ApprovalStatus status) {
		dao.addApproval(new Approval(userName, clientId, scope, expiresIn, status));
	}

	private SecurityContextAccessor mockSecurityContextAccessor(String userName) {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		when(sca.getUserName()).thenReturn(userName);
		when(sca.isUser()).thenReturn(true);
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
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);

		assertEquals(3, endpoints.getApprovals("userName pr", 1, 100).size());
		assertEquals(2, endpoints.getApprovals("userName pr", 1, 2).size());
	}

	@Test
	public void canGetApprovalsWithAutoApproveTrue() {
		//Only get scopes that need approval
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);

		assertEquals(3, endpoints.getApprovals("userName eq 'marissa'", 1, 100).size());

		addApproval("marissa", "c1", "read", 12000, DENIED);
		addApproval("marissa", "c1", "write", 6000, APPROVED);

		assertEquals(3, endpoints.getApprovals("userName eq 'marissa'", 1, 100).size());
	}

	@Test
	public void canUpdateApprovals() {
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);

		Approval[] app = new Approval[] {new Approval("marissa", "c1", "uaa.user", 2000, APPROVED),
														  new Approval("marissa", "c1", "dash.user", 2000, APPROVED),
														  new Approval("marissa", "c1", "openid", 2000, DENIED),
														  new Approval("marissa", "c1", "cloud_controller.read", 2000, APPROVED)};
		List<Approval> response = endpoints.updateApprovals(app);
		assertEquals(4, response.size());
		assertTrue(response.contains(new Approval("marissa", "c1", "uaa.user", 2000, APPROVED)));
		assertTrue(response.contains(new Approval("marissa", "c1", "dash.user", 2000, APPROVED)));
		assertTrue(response.contains(new Approval("marissa", "c1", "openid", 2000, DENIED)));
		assertTrue(response.contains(new Approval("marissa", "c1", "cloud_controller.read", 2000, APPROVED)));

		List<Approval> updatedApprovals = endpoints.getApprovals("userName eq 'marissa'", 1, 100);
		assertEquals(4, updatedApprovals.size());
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "dash.user", 2000, APPROVED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "openid", 2000, DENIED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "cloud_controller.read", 2000, APPROVED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "uaa.user", 2000, APPROVED)));
	}

	public void attemptingToCreateDuplicateApprovalsExtendsValidity() {
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);

		addApproval("marissa", "c1", "openid", 10000, APPROVED);

		List<Approval> updatedApprovals = endpoints.getApprovals("userName eq 'marissa'", 1, 100);
		assertEquals(3, updatedApprovals.size());
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "uaa.user", 6000, APPROVED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "uaa.admin", 12000, DENIED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "openid", 10000, APPROVED)));
	}

	public void attemptingToCreateAnApprovalWithADifferentStatusUpdatesApproval() {
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);

		addApproval("marissa", "c1", "openid", 18000, DENIED);

		List<Approval> updatedApprovals = endpoints.getApprovals("userName eq 'marissa'", 1, 100);
		assertEquals(4, updatedApprovals.size());
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "uaa.user", 6000, APPROVED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "uaa.admin", 12000, DENIED)));
		assertTrue(updatedApprovals.contains(new Approval("marissa", "c1", "openid", 18000, DENIED)));
	}


	@Test (expected = UaaException.class)
	public void userCannotUpdateApprovalsForAnotherUser() {
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);
		endpoints.setSecurityContextAccessor(mockSecurityContextAccessor("vidya"));
		endpoints.updateApprovals(new Approval[] {new Approval("marissa", "c1", "uaa.user", 2000, APPROVED)});
	}

	@Test
	public void canRevokeApprovals() {
		addApproval("marissa", "c1", "uaa.user", 6000, APPROVED);
		addApproval("marissa", "c1", "uaa.admin", 12000, DENIED);
		addApproval("marissa", "c1", "openid", 6000, APPROVED);

		assertEquals(3, endpoints.getApprovals("userName pr", 1, 100).size());
		assertEquals("ok", endpoints.revokeApprovals("c1").getStatus());
		assertEquals(0, endpoints.getApprovals("userName pr", 1, 100).size());
	}
}
