package org.cloudfoundry.identity.uaa.scim;

/**
 * @author Luke Taylor
 */
public interface ScimUserProvisioning {
	public ScimUser retrieveUser(String id);

	public ScimUser createUser(ScimUser user);

	public ScimUser updateUser(String id, ScimUser user);
}
