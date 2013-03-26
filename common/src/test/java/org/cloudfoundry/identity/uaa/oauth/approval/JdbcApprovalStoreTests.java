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

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.rest.jdbc.SimpleSearchQueryConverter;
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

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb", "test,mysql"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcApprovalStoreTests {
	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcApprovalStore dao;

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		dao = new JdbcApprovalStore(template, new SimpleSearchQueryConverter());

		addApproval("u1", "c1", "uaa.user", 6000, APPROVED);
		addApproval("u1", "c2", "uaa.admin", 12000, DENIED);
		addApproval("u2", "c1", "openid", 6000, APPROVED);
	}

	private void addApproval(String userName, String clientId, String scope, long expiresIn, ApprovalStatus status) {
		Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
		Date lastUpdatedAt = new Date();
		Approval newApproval = new Approval(userName, clientId, scope, expiresAt, status, lastUpdatedAt);
		dao.addApproval(newApproval);
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "authz_approvals");
		assertEquals(0, template.queryForInt("select count(*) from authz_approvals"));
	}

	@Test
	public void testAddAndGetApproval() {
		String userName = "user";
		String clientId = "client";
		String scope = "uaa.user";
		long expiresIn = 1000l;
		Date lastUpdatedAt = new Date();
		ApprovalStatus status = APPROVED;

		Date expiresAt = new Timestamp(new Date().getTime() + expiresIn);
		Approval newApproval = new Approval(userName, clientId, scope, expiresAt, status, lastUpdatedAt);
		dao.addApproval(newApproval);
		List<Approval> approvals = dao.getApprovals(userName, clientId);

		Approval approval = approvals.get(0);
		assertEquals(clientId, approval.getClientId());
		assertEquals(userName, approval.getUserName());
		assertEquals(Math.round(expiresAt.getTime() / 1000), Math.round(approval.getExpiresAt().getTime() / 1000));
		assertEquals(Math.round(lastUpdatedAt.getTime() / 1000), Math.round(approval.getLastUpdatedAt().getTime() / 1000));
		assertEquals(scope, approval.getScope());
		assertEquals(status, approval.getStatus());
	}

	@Test
	public void canGetApprovals() {
		assertEquals(3, dao.getApprovals("userName pr").size());
		assertEquals(1, dao.getApprovals("u2", "c1").size());
		assertEquals(0, dao.getApprovals("u2", "c2").size());
		assertEquals(1, dao.getApprovals("u1", "c1").size());
	}

	@Test
	public void canAddApproval() {
		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 12000, APPROVED)));
		List<Approval> apps = dao.getApprovals("u2", "c2");
		assertEquals(1, apps.size());
		Approval app = apps.iterator().next();
		assertEquals("dash.user", app.getScope());
		assertTrue(app.getExpiresAt().after(new Date()));
		assertEquals(APPROVED, app.getStatus());
	}

	@Test
	public void canRevokeApprovals() {
		assertEquals(2, dao.getApprovals("userName eq 'u1'").size());
		assertTrue(dao.revokeApprovals("userName eq 'u1'"));
		assertEquals(0, dao.getApprovals("userName eq 'u1'").size());
	}

	@Test
	public void addSameApprovalRepeatedlyUpdatesExpiry() {
		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 6000, APPROVED)));
		Approval app = dao.getApprovals("u2", "c2").iterator().next();
		assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 6000) / 1000));

		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 8000, APPROVED)));
		app = dao.getApprovals("u2", "c2").iterator().next();
		assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 8000) / 1000));
	}

	@Test
	public void addSameApprovalDifferentStatusRepeatedlyOnlyUpdatesStatus() {
		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 6000, APPROVED)));
		Approval app = dao.getApprovals("u2", "c2").iterator().next();
		assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 6000) / 1000));

		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 8000, DENIED)));
		app = dao.getApprovals("u2", "c2").iterator().next();
		assertEquals(Math.round(app.getExpiresAt().getTime() / 1000), Math.round((new Date().getTime() + 6000) / 1000));
		assertEquals(DENIED, app.getStatus());
	}

	@Test
	public void canRefreshApproval() {
		Approval app = dao.getApprovals("u1", "c1").iterator().next();
		Date now = new Date();

		dao.refreshApproval(new Approval(app.getUserName(), app.getClientId(), app.getScope(), now, APPROVED));
		app = dao.getApprovals("u1", "c1").iterator().next();
		assertEquals(Math.round(now.getTime() / 1000), Math.round(app.getExpiresAt().getTime() / 1000));
	}

	@Test
	public void canPurgeExpiredApprovals() throws InterruptedException {
		List<Approval> approvals = dao.getApprovals("userName pr");
		assertEquals(3, approvals.size());
		addApproval("u3", "c3", "test1", 0, APPROVED);
		addApproval("u3", "c3", "test2", 0, DENIED);
		addApproval("u3", "c3", "test3", 0, APPROVED);
		List<Approval> newApprovals = dao.getApprovals("userName pr");
		assertEquals(6, newApprovals.size());

		// On mysql, the expiry is rounded off to the nearest second so
		// the following assert could randomly fail.
		Thread.sleep(500);
		dao.purgeExpiredApprovals();
		List<Approval> remainingApprovals = dao.getApprovals("userName pr");
		assertEquals(3, remainingApprovals.size());
	}

}
