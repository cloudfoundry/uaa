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
package org.cloudfoundry.identity.uaa.audit;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PrincipalAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.junit.Assert.assertEquals;

import java.sql.Timestamp;
import java.util.List;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 */
@ContextConfiguration ("classpath:/test-data-source.xml")
@RunWith (SpringJUnit4ClassRunner.class)
@IfProfileValue (name = "spring.profiles.active", values = { "" , "hsqldb", "test,postgresql", "test,mysql" })
@ProfileValueSourceConfiguration (NullSafeSystemProfileValueSource.class)
public class JdbcAuditServiceTests {

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcAuditService auditService;

	private String authDetails;

	@Before
	public void createService() throws Exception {
		template = new JdbcTemplate(dataSource);
		auditService = new JdbcAuditService(dataSource);
		template.execute("DELETE FROM sec_audit WHERE principal_id='1' or principal_id='clientA' or principal_id='clientB'");
		authDetails = "1.1.1.1";
	}

	@Test
	public void userAuthenticationFailureAuditSucceeds() throws Exception {
		auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
		Thread.sleep(100);
		auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"));
		List<AuditEvent> events = auditService.find("1", 0);
		assertEquals(2, events.size());
		assertEquals("1", events.get(0).getPrincipalId());
		assertEquals("joe", events.get(0).getData());
		assertEquals("1.1.1.1", events.get(0).getOrigin());
	}

	@Test
	public void principalAuthenticationFailureAuditSucceeds() {
		auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"));
		List<AuditEvent> events = auditService.find("clientA", 0);
		assertEquals(1, events.size());
		assertEquals("clientA", events.get(0).getPrincipalId());
		assertEquals("1.1.1.1", events.get(0).getOrigin());
	}

	@Test
	public void findMethodOnlyReturnsEventsWithinRequestedPeriod() {
		long now = System.currentTimeMillis();
		auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"));
		// Set the created column to one hour past
		template.update("update sec_audit set created=?", new Timestamp(now - 3600*1000));
		auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientA"));
		auditService.log(getAuditEvent(PrincipalAuthenticationFailure, "clientB"));
		// Find events within last 2 mins
		List<AuditEvent> events = auditService.find("clientA", now - 120*1000);
		assertEquals(1, events.size());
	}

	private AuditEvent getAuditEvent(AuditEventType type, String principal) {
		return getAuditEvent(type, principal, null);
	}

	private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
		return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis());
	}

}

