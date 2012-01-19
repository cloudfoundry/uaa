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
