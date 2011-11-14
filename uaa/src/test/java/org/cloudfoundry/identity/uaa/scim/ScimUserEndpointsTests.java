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
import static org.junit.Assert.assertTrue;
import static org.junit.internal.matchers.StringContains.containsString;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.InMemoryUaaUserDatabase;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpStatus;

/**
 * @author Dave Syer
 * 
 */
public class ScimUserEndpointsTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private ScimUser joel = new ScimUser("jdsa");

	private ScimUser dale = new ScimUser("olds");

	private InMemoryUaaUserDatabase dao = new InMemoryUaaUserDatabase();;

	public ScimUserEndpointsTests() {
		joel.addEmail("jdsa@vmware.com");
		dale.addEmail("olds@vmware.com");
		joel = dao.createUser(joel);
		dale = dao.createUser(dale);
	}

	@Test
	public void testInvalidFilterExpression() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		expected.expect(new ScimExceptionStatusCodeMatcher(HttpStatus.BAD_REQUEST));
		expected.expectMessage(containsString("Invalid filter"));
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName qq 'd'", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsByUserName() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName eq 'jdsa'", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
		assertEquals(joel.getId(), results.getResources().iterator().next().get("id"));
	}

	@Test
	public void testFindIdsByUserNameContains() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd'", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsByNameExists() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "name pr", 1, 100);
		assertEquals(0, results.getTotalResults());
	}

	@Test
	public void testFindIdsByUserNameStartWith() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName sw 'j'", 1, 100);
		assertEquals(1, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	@Test
	public void testFindIdsWithBooleanExpression() {
		ScimUserEndpoints endpoints = new ScimUserEndpoints();
		endpoints.setDao(dao);
		SearchResults<Map<String, Object>> results = endpoints.findUsers("id", "userName co 'd' and id pr", 1, 100);
		assertEquals(2, results.getTotalResults());
		assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
				.contains(joel.getId()));
	}

	private Collection<Object> getSetFromMaps(Collection<Map<String, Object>> resources, String key) {
		Collection<Object> result = new ArrayList<Object>();
		for (Map<String, Object> map : resources) {
			result.add(map.get(key));
		}
		return result;
	}

}
