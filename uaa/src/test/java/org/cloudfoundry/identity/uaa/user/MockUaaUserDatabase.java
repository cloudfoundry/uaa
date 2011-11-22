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
