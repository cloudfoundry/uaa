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
