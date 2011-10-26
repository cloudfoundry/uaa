/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.collaboration.simple.capability;

import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.PermissionChecker;

/**
 * Permission checker that allows user full write access to a project with his name. Used as a
 * fallback for users that have not been properly assigned collaboration permissions.
 * 
 * @author Dave Syer
 * 
 */
public class DynamicDefaultPermissionChecker implements PermissionChecker {

	@Override
	public boolean isPermitted(Resource resource, User user, Permission permission) {
		if (resource instanceof Project && resource.getName().equals(user.getName())) {
			return Permission.WRITE.contains(permission);
		}
		throw new IllegalArgumentException("No Org registered for this resource: " + resource);
	}

}
