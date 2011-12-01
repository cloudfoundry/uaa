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

import java.util.Map;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * In-memory user account information storage.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryUaaUserDatabase implements UaaUserDatabase {

	private final Map<String, UaaUser> users;

	public InMemoryUaaUserDatabase(Map<String, UaaUser> users) {
		this.users = users;
	}

	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {

		UaaUser u = users.get(username);
		if (u == null) {
			throw new UsernameNotFoundException("User " + username + " not found");
		}
		return u;

	}

}
