/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.audit;

import javax.sql.DataSource;

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.TestUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
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
@IfProfileValue (name = "spring.profiles.active", values = { "" , "jdbc" })
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
	public void principalAuthenticationFailureAuditSucceeds() throws Exception {
		auditService.principalAuthenticationFailure("clientA", authDetails);

		String origin = template.queryForObject("select origin from sec_audit where principal_id='clientA'",String.class);
		assertEquals("1.1.1.1", origin);
	}
}
