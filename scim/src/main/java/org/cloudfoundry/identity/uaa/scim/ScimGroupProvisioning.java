package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.rest.Queryable;
import org.cloudfoundry.identity.uaa.rest.ResourceManager;

public interface ScimGroupProvisioning extends ResourceManager<ScimGroup>, Queryable<ScimGroup> {
}
