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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;

/**
 * @author Dave Syer
 * 
 */
public class SimpleProject extends BaseResource implements Project {

	private final Set<Resource> resources;

	public SimpleProject(String name) {
		this(name, null);
	}

	public SimpleProject(String name, PermissionChecker checker) {
		this(name, Collections.<Resource>emptySet(), checker);
	}

	public SimpleProject(String name, Collection<? extends Resource> resources, PermissionChecker checker) {
		super(name, "projects", checker);
		this.resources = new HashSet<Resource>(resources);
	}

	@Override
	public Nature getNature() {
		return Nature.CONTAINER;
	}

	@Override
	public Set<Resource> getResources() {
		return Collections.unmodifiableSet(resources);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((resources == null) ? 0 : resources.hashCode());
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
		SimpleProject other = (SimpleProject) obj;
		if (resources == null) {
			if (other.resources != null)
				return false;
		} else if (!resources.equals(other.resources))
			return false;
		return true;
	}

}
