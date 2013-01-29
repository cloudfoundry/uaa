/*
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

	public void updateUser(String username, UaaUser user) throws UsernameNotFoundException {

		if (!users.containsKey(username)) {
			throw new UsernameNotFoundException("User " + username + " not found");
		}
		users.put(username, user);
	}

}
