package org.cloudfoundry.identity.uaa.user;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * In-memory user account information storage.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryUaaUserDatabase implements UaaUserDatabase, ScimUserProvisioning {

	private final Log logger = LogFactory.getLog(getClass());

	private int counter = 1;

	private final Map<String, UaaUser> userDb = new HashMap<String, UaaUser>();

	public InMemoryUaaUserDatabase() {
	}

	public InMemoryUaaUserDatabase(List<UaaUser> users) {
		for (UaaUser user : users) {
			addUser(user);
		}
	}

	private UaaUser addUser(UaaUser user) {
		userDb.put(user.getUsername(), user.id(counter++));

		return userDb.get(user.getUsername());
	}

	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		UaaUser u = userDb.get(username);

		if (u == null) {
			throw new UsernameNotFoundException("User " + username + " not found");
		}

		return u;
	}

	// Scim interface

	@Override
	public ScimUser retrieveUser(String id) {
		for (UaaUser user : userDb.values()) {
			if (user.getId().equals(id)) {
				return user.scimUser();
			}
		}
		throw new ScimException("User " + id + " does not exist", HttpStatus.NOT_FOUND);
	}

	@Override
	public Collection<ScimUser> retrieveUsers() {
		Collection<ScimUser> users = new ArrayList<ScimUser>();
		for (UaaUser user : userDb.values()) {
			users.add(user.scimUser());
		}
		return users;
	}

	@Override
	public ScimUser removeUser(String id) {
		UaaUser removed = userDb.remove(id);
		if (removed == null) {
			throw new ScimException("User " + id + " does not exist", HttpStatus.NOT_FOUND);
		}
		return removed.scimUser();
	}

	@Override
	public ScimUser createUser(ScimUser scim, String password) {
		Assert.isTrue(!userDb.containsKey(scim.getUserName()), "A user with name '" + scim.getUserName()
				+ "' already exists");
		Assert.notEmpty(scim.getEmails(), "At least one email is required");

		try {
			UaaUser uaaUser = addUser(new UaaUser(scim, password));

			return uaaUser.scimUser();
		}
		catch (IllegalArgumentException e) {
			throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}

	@Override
	public ScimUser updateUser(String id, ScimUser user) {
		return null;
	}
}
