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

import java.security.SecureRandom;
import java.util.Random;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Hex;

/**
 * Really simple {@link UaaUserDatabase} that doesn't use any backend store. All users retrieved have the same name
 * ("Legacy User") and differ only in their username. Used in conjuction with other legacy components to allow delegated
 * authentication (i.e. this app doesn't do authentication, it just trusts a remote source).
 *
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class LegacyUaaUserDatabase implements UaaUserDatabase {
	// Saves us using an empty string as a password
	private final String dummyPassword;

	public LegacyUaaUserDatabase() {
		Random passwordGenerator = new SecureRandom();
		byte[] bytes = new byte[16];
		passwordGenerator.nextBytes(bytes);
		dummyPassword = new String(Hex.encode(bytes));
	}

	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		String email = username;
		if (!email.contains("@")) {
			email = email + "@test.org";
		}
		return new UaaUser(username, dummyPassword, email , "Legacy", "User");
	}

}
