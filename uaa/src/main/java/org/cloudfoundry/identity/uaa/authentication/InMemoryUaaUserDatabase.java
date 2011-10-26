package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 */
public class InMemoryUaaUserDatabase implements UaaUserService {
	private final Map<String, UaaUser> userDb = new HashMap<String,UaaUser>();

	public InMemoryUaaUserDatabase(List<UaaUser> users) {
		for (UaaUser user : users) {
			userDb.put(user.getUsername(), user);
		}
	}

	@Override
	public UaaUser getUser(String username) throws UsernameNotFoundException {
		UaaUser u = userDb.get(username);

		if (u == null) {
			throw new UsernameNotFoundException("User " + username + " not found");
		}

		return u;
	}

	@Override
	public UaaPrincipal getPrincipal(UaaUser user) {
		return new UaaPrincipal(String.valueOf(user.getUsername().hashCode()), user.getUsername());
	}
}
