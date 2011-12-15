/*
 * Copyright 2006-2010 the original author or authors.
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

package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.io.FileSystemResource;

/**
 * @author Dave Syer
 *
 */
public class BootstrapTests {
	
	
	@After
	public void cleanup() {
		System.clearProperty("spring.profiles.active");		
	}

	@Test
	public void testRootContextWithJdbcUsers() throws Exception {
		System.setProperty("spring.profiles.active", "jdbc,hsqldb");
		GenericXmlApplicationContext context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
		context.close();
	}

	@Test
	public void testRootContextWithDevUsers() throws Exception {
		GenericXmlApplicationContext context = new GenericXmlApplicationContext(new FileSystemResource("src/main/webapp/WEB-INF/spring-servlet.xml"));
		assertNotNull(context.getBean("userDatabase", InMemoryUaaUserDatabase.class));
		context.close();
	}

}
