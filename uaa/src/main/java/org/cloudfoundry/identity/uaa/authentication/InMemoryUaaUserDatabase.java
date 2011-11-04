package org.cloudfoundry.identity.uaa.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * In-memory user account information storage.
 *
 * @author Luke Taylor
 */
public class InMemoryUaaUserDatabase implements UaaUserService, ScimUserProvisioning {
	private final Log logger = LogFactory.getLog(getClass());
	private int counter = 1;

	private final Map<String, UaaUser> userDb = new HashMap<String,UaaUser>();

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
	public UaaUser getUser(String username) throws UsernameNotFoundException {
		UaaUser u = userDb.get(username);

		if (u == null) {
			throw new UsernameNotFoundException("User " + username + " not found");
		}

		return u;
	}

	@Override
	public UaaPrincipal getPrincipal(UaaUser user) {
		return new UaaPrincipal(String.valueOf(user.getUsername().hashCode()), user.getUsername(), user.getEmail());
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
	public ScimUser createUser(ScimUser scim) {
		Assert.isTrue(!userDb.containsKey(scim.getUserName()), "A user with name '" + scim.getUserName() +
				"' already exists");
		Assert.notEmpty(scim.getEmails(), "At least one email is required");

		try {
			UaaUser uaaUser = addUser(new UaaUser(scim));

			return uaaUser.scimUser();
		} catch(IllegalArgumentException e) {
			throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}

	@Override
	public ScimUser updateUser(String id, ScimUser user) {
		return null;
	}
}
