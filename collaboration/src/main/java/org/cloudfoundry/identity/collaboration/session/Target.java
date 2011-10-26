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

package org.cloudfoundry.identity.collaboration.session;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.PermissionChecker;

/**
 * @author Dave Syer
 * 
 */
public class Target implements PermissionChecker {

	private final Org org;
	private final Project project;

	public Target(Org org, Project project) {
		this.org = org;
		this.project = project;
	}

	@Override
	public boolean isPermitted(Resource resource, User user, Permission permission) {
		return resource.isPermitted(user, permission);
	}

	public Org getOrg() {
		return org;
	}

	public Project getProject() {
		return project;
	}

	public boolean isPermittedToDelegate(User master) {
		return org.isPermitted(master, Permission.DELEGATE);
	}

}
