package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.cloudfoundry.identity.uaa.resources.ResourceManager;

public interface ScimGroupProvisioning extends ResourceManager<ScimGroup>, Queryable<ScimGroup> {

  ScimGroup createOrGet(ScimGroup group, String zoneId);

  ScimGroup getByName(String displayName, String zoneId);
}
