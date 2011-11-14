/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.scim;

import static org.junit.Assert.assertEquals;

import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class ScimUserEndpointsTests {

	private ScimUser joel = new ScimUser("jdsa");

	private ScimUser dale = new ScimUser("olds");

	private InMemoryUaaUserDatabase dao = new InMemoryUaaUserDatabase();;

	public ScimUserEndpointsTests() {
		joel.setName(new Name("Joel", "D'sa"));
		joel.addEmail("jdsa@vmware.com");
		dale.setName(new Name("Dale", "Olds"));
		dale.addEmail("olds@vmware.com");
		joel = dao.createUser(joel);
		dale = dao.createUser(dale);
	}

	@Test
	public void testFindAll() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName eq 'jdsa'", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertEquals(1, results.getSchemas().size());
		// System.err.println(results.getValues());
		assertEquals(joel.getId(), results.getResources().iterator().next().get("id"));
	}

}
