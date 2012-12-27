package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import java.util.List;

public interface ScimGroupProvisioning extends ResourceManager<ScimGroup>, Queriable<ScimGroup> {
}
