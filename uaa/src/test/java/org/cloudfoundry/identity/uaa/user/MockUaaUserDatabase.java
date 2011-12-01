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

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Date;

/**
 * @author Luke Taylor
 */
public class MockUaaUserDatabase implements UaaUserDatabase {
	UaaUser user;

	public MockUaaUserDatabase(String id, String name, String email, String givenName, String familyName) {
		user = new UaaUser(id, name, "", email, givenName, familyName, new Date(), new Date());
	}


	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		if (user.getUsername().equals(username)) {
			return user;
		} else {
			throw new UsernameNotFoundException(username);
		}
	}
}
