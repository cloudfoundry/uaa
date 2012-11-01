package org.cloudfoundry.identity.uaa.scim.groups;

import org.cloudfoundry.identity.uaa.scim.core.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.core.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.core.ScimResourceNotFoundException;

import java.util.List;

public interface ScimGroupProvisioning {

	public List<ScimGroup> retrieveGroups();

	public List<ScimGroup> retrieveGroups(String filter);

	public List<ScimGroup> retrieveGroups(String filter, String sortBy, boolean ascending);

	public ScimGroup retrieveGroup(String id) throws ScimResourceNotFoundException;

	public ScimGroup createGroup(ScimGroup group) throws InvalidScimResourceException, ScimResourceAlreadyExistsException;

	public ScimGroup updateGroup(String id, ScimGroup group) throws InvalidScimResourceException, ScimResourceNotFoundException;

	public ScimGroup removeGroup(String id, int version) throws ScimResourceNotFoundException;
}
