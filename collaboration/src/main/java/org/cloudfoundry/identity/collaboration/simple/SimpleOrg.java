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

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;

/**
 * @author Dave Syer
 * 
 */
public class SimpleOrg extends BaseResource implements Org {

	private final Set<Project> projects;

	public SimpleOrg(String name) {
		this(name, null);
	}

	public SimpleOrg(String name, PermissionChecker checker) {
		this(name, Collections.<Project>emptySet(), checker);
	}

	public SimpleOrg(String name, Collection<? extends Project> projects, PermissionChecker checker) {
		super(name, "orgs", checker);
		this.projects = new HashSet<Project>(projects);
	}

	@Override
	public Nature getNature() {
		return Nature.CONTAINER;
	}

	@Override
	public Set<Resource> getResources() {
		Set<Resource> resources = new HashSet<Resource>();
		for (Project project : projects) {
			resources.addAll(project.getResources());
		}
		return resources;
	}

	@Override
	public Set<Resource> getResources(String type) {
		type = type.toLowerCase();
		Set<Resource> resources = new HashSet<Resource>();
		for (Project project : projects) {
			for (Resource resource : project.getResources()) {
				if (type.equals(resource.getType())) {
					resources.add(resource);
				}
			}
		}
		return resources;
	}

	@Override
	public Set<Project> getProjects() {
		synchronized (projects) {
			return Collections.unmodifiableSet(projects);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((projects == null) ? 0 : projects.hashCode());
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
		SimpleOrg other = (SimpleOrg) obj;
		if (projects == null) {
			if (other.projects != null)
				return false;
		} else if (!projects.equals(other.projects))
			return false;
		return true;
	}

}
