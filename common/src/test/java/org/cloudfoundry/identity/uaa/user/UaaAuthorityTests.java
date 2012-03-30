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
package org.cloudfoundry.identity.uaa.user;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class UaaAuthorityTests {

	@Test
	public void testGetAuthority() {
		assertEquals("ROLE_USER", UaaAuthority.ROLE_USER.getAuthority());
	}

	@Test
	public void testValueOf() {
		assertEquals(0, UaaAuthority.ROLE_USER.value());
		assertEquals(1, UaaAuthority.ROLE_ADMIN.value());
	}

	@Test
	public void testFromUserType() {
		assertEquals(UaaAuthority.ROLE_USER, UaaAuthority.fromUserType("User"));
	}

	@Test
	public void testFromUserTypeWithPrefix() {
		assertEquals(UaaAuthority.ROLE_USER, UaaAuthority.fromUserType("ROLE_USER"));
	}

	@Test
	public void testAdminFromUserType() {
		assertEquals(UaaAuthority.ROLE_ADMIN, UaaAuthority.fromUserType("Admin"));
	}

}
