package org.cloudfoundry.identity.uaa.scim;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public interface ScimUserProvisioning {

	public ScimUser retrieveUser(String id);

	public ScimUser createUser(ScimUser user);

	public ScimUser updateUser(String id, ScimUser user);

	public ScimUser removeUser(String id);

}
