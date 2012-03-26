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
package org.cloudfoundry.identity.uaa.user;

import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.jdbc.core.JdbcOperations;

/**
 * @author Dave Syer
 *
 */
public class JdbcUaaAdminUserBootstrapTests {

	/**
	 * Test method for {@link org.cloudfoundry.identity.uaa.user.JdbcUaaAdminUserBootstrap#start()}.
	 */
	@Test
	public void testStart() {
		JdbcOperations jdbcTemplate = Mockito.mock(JdbcOperations.class);
		JdbcUaaAdminUserBootstrap bootstrap = new JdbcUaaAdminUserBootstrap(jdbcTemplate);
		bootstrap.start();
		// Mockito.verify(jdbcTemplate).update(Mockito.contains("insert into users"));
	}

}
