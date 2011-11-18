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
package org.cloudfoundry.identity.uaa.authentication;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Dave Syer
 *
 */
public class UaaTestFactory {

	public static UaaPrincipal getPrincipal(String id, String name, String email) {
		return new UaaPrincipal(new MockUaaUserDatabase(id, name, email).retrieveUserByName(name));
	}

	public static UaaUser getUser(String id, String name, String email) {
		return new MockUaaUserDatabase(id, name, email).retrieveUserByName(name);
	}

	public static UaaAuthentication getAuthentication(String id, String name, String email) {
		return new UaaAuthentication(getPrincipal(id, name, email),
				Arrays.<GrantedAuthority> asList(new SimpleGrantedAuthority("ROLE_USER")));
	}

	public static ScimUser getScimUser(String name, String email, String givenName, String familyName) {
		ScimUser user = new ScimUser(null, name, givenName, familyName);
		user.addEmail(email);
		return user;
	}

}
