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

import java.sql.Timestamp;
import java.util.List;
import javax.sql.DataSource;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.cloudfoundry.identity.uaa.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.TestUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 */
@ContextConfiguration ("classpath:/test-data-source.xml")
@RunWith (SpringJUnit4ClassRunner.class)
@IfProfileValue (name = "spring.profiles.active", values = { "" , "hsqdb" })
@ProfileValueSourceConfiguration (NullSafeSystemProfileValueSource.class)
public class JdbcAuditServiceTests {

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcAuditService auditService;

	private UaaAuthenticationDetails authDetails;

	@Before
	public void createService() throws Exception {
		template = new JdbcTemplate(dataSource);
		TestUtils.createSchema(dataSource);
		auditService = new JdbcAuditService(dataSource);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("1.1.1.1");
		authDetails = new UaaAuthenticationDetails(request);
	}

	@Test
	public void userAuthenticationFailureAuditSucceeds() throws Exception {
		UaaUser joe = mock(UaaUser.class);
		when(joe.getId()).thenReturn("1");
		when(joe.getUsername()).thenReturn("joe");
		auditService.userAuthenticationFailure(joe, authDetails);
		Thread.sleep(100);
		auditService.userAuthenticationFailure(joe, authDetails);
		List<AuditEvent> events = auditService.find("1", 0);
		assertEquals(2, events.size());
		assertEquals("1", events.get(0).getPrincipalId());
		assertEquals("joe", events.get(0).getData());
		assertEquals("1.1.1.1", events.get(0).getOrigin());
	}

	@Test
	public void principalAuthenticationFailureAuditSucceeds() {
		auditService.principalAuthenticationFailure("clientA", authDetails);
		List<AuditEvent> events = auditService.find("clientA", 0);
		assertEquals(1, events.size());
		assertEquals("clientA", events.get(0).getPrincipalId());
		assertEquals("1.1.1.1", events.get(0).getOrigin());
	}

	@Test
	public void findMethodOnlyReturnsEventsWithinRequestedPeriod() {
		long now = System.currentTimeMillis();
		auditService.principalAuthenticationFailure("clientA", authDetails);
		// Set the created column to one hour past
		template.update("update sec_audit set created=?", new Timestamp(now - 3600*1000));
		auditService.principalAuthenticationFailure("clientA", authDetails);
		auditService.principalAuthenticationFailure("clientB", authDetails);
		// Find events within last 2 mins
		List<AuditEvent> events = auditService.find("clientA", now - 120*1000);
		assertEquals(1, events.size());
	}

}

