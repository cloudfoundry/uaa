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

package org.cloudfoundry.identity.collaboration.simple;

import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;

/**
 * @author Dave Syer
 *
 */
public abstract class BaseResource extends NamedEntity implements Resource {

	private final String type;
	private final PermissionChecker checker;

	protected BaseResource(String name, String type, PermissionChecker checker) {
		super(name);
		this.type = type;
		this.checker = checker;
	}
	
	@Override
	public String getType() {
		return this.type;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((type == null) ? 0 : type.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		BaseResource other = (BaseResource) obj;
		if (type == null) {
			if (other.type != null)
				return false;
		} else if (!type.equals(other.type))
			return false;
		return true;
	}

	@Override
	public boolean isPermitted(User user, Permission permission) {
		// Permissions are hierarchical in this implementation
		if (checker!=null) {
			return checker.isPermitted(this, user, permission);
		}
		return false;
	}

}