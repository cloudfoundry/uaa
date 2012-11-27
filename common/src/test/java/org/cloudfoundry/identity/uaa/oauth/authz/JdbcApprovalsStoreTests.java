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
package org.cloudfoundry.identity.uaa.oauth.authz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

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
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcApprovalsStoreTests {
	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcApprovalsStore dao;

	private static final String addApprovalSqlFormat = "insert into authz_approvals (userName, clientId, scope, expiresAt) values ('%s','%s','%s','%s')";

	@Before
	public void createDatasource() {

		template = new JdbcTemplate(dataSource);

		dao = new JdbcApprovalsStore(template);

		addApproval("u1", "c1", "uaa.user", 6000);
		addApproval("u1", "c2", "uaa.admin", 12000);
		addApproval("u2", "c1", "openid", 6000);
	}

	private void addApproval(String userName, String clientId, String scope, long expiresIn) {
		template.execute(String.format(addApprovalSqlFormat, userName, clientId, scope, new Timestamp(new Date().getTime() + expiresIn)));
	}

	@After
	public void cleanupDataSource() throws Exception {
		TestUtils.deleteFrom(dataSource, "authz_approvals");
		assertEquals(0, template.queryForInt("select count(*) from authz_approvals"));
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
		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 12000)));
		List<Approval> apps = dao.getApprovals("u2", "c2");
		assertEquals(1, apps.size());
		Approval app = apps.iterator().next();
		assertEquals("dash.user", app.getScope());
		assertTrue(app.getExpiresAt().after(new Date()));
	}

	@Test
	public void canRevokeApprovals() {
		assertEquals(2, dao.getApprovals("userName eq 'u1'").size());
		assertTrue(dao.revokeApprovals("userName eq 'u1'"));
		assertEquals(0, dao.getApprovals("userName eq 'u1'").size());
	}

	@Test
	public void addSameApprovalRepeatedlyUpdatesExpiry() {
		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 6000)));
		Approval app = dao.getApprovals("u2", "c2").iterator().next();
		assertTrue(app.getExpiresAt().before(new Date(new Date().getTime() + 6000)));

		assertTrue(dao.addApproval(new Approval("u2", "c2", "dash.user", 8000)));
		app = dao.getApprovals("u2", "c2").iterator().next();
		assertTrue(app.getExpiresAt().after(new Date(new Date().getTime() + 6000)));
	}

	@Test
	public void canRefreshApproval() {
		Approval app = dao.getApprovals("u1", "c1").iterator().next();
		assertTrue(app.getExpiresAt().before(new Date(new Date().getTime() + 6000)));

		assertTrue(dao.refreshApproval(new Approval(app.getUserName(), app.getClientId(), app.getScope(), app.getExpiresAt().getTime() + 2000)));
		app = dao.getApprovals("u1", "c1").iterator().next();
		assertTrue(app.getExpiresAt().after(new Date(new Date().getTime() + 6000)));
	}

	@Test
	public void canPurgeExpiredApprovals() {
		assertEquals(3, dao.getApprovals("userName pr").size());
		addApproval("u3", "c3", "test1", 0);
		addApproval("u3", "c3", "test2", 0);
		addApproval("u3", "c3", "test3", 0);
		assertEquals(6, dao.getApprovals("userName pr").size());

		dao.purgeExpiredApprovals();
		assertEquals(3, dao.getApprovals("userName pr").size());
	}

}
