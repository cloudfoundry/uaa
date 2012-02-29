/**
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

import java.security.SecureRandom;
import java.util.Random;

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
