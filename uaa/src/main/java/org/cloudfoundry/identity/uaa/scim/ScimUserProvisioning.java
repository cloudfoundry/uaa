package org.cloudfoundry.identity.uaa.scim;

import java.util.Collection;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public interface ScimUserProvisioning {

	public ScimUser retrieveUser(String id) throws UserNotFoundException;

	public Collection<ScimUser> retrieveUsers();

	public Collection<ScimUser> retrieveUsers(String filter);

	public ScimUser createUser(ScimUser user, String password) throws InvalidPasswordException, InvalidUserException;

	public ScimUser updateUser(String id, ScimUser user) throws InvalidUserException, UserNotFoundException;

	public ScimUser removeUser(String id, int version) throws UserNotFoundException;

}
