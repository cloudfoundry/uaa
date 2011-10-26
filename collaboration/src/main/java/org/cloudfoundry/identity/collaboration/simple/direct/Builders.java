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

package org.cloudfoundry.identity.collaboration.simple.direct;

import java.util.Collection;
import java.util.HashSet;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.simple.SimpleOrg;
import org.cloudfoundry.identity.collaboration.simple.SimpleProject;
import org.cloudfoundry.identity.collaboration.simple.SimpleResource;

/**
 * @author Dave Syer
 *
 */
public class Builders {

	public static class OrgBuilder extends GenericResourceBuilder<OrgBuilder, Org> {
	
		private Collection<SimpleProject> projects = new HashSet<SimpleProject>();
	
		public OrgBuilder(DirectPermissionChecker checker) {
			super(checker);
		}
		
		@Override
		protected Org doBuild() {
			SimpleOrg org = new SimpleOrg(getName(), projects, getPermissionChecker());
			return org;
		}
	
		public OrgBuilder addProject(SimpleProject project) {
			this.projects.add(project);
			return this;
		}
	
	}

	public static class ProjectBuilder extends GenericResourceBuilder<ProjectBuilder, SimpleProject> {
	
		private Collection<SimpleResource> resources = new HashSet<SimpleResource>();
	
		public ProjectBuilder(DirectPermissionChecker checker) {
			super(checker);
		}
		
		@Override
		protected SimpleProject doBuild() {
			SimpleProject project = new SimpleProject(getName(), resources, getPermissionChecker());
			return project;
		}
	
		public ProjectBuilder addResource(SimpleResource resource) {
			this.resources.add(resource);
			return this;
		}
	
	}

	public static class ResourceBuilder extends GenericResourceBuilder<ResourceBuilder, SimpleResource> {
	
		public ResourceBuilder(DirectPermissionChecker checker, String name, SimpleResource.Type type) {
			super(checker);
			super.name(name);
			super.type(type.toString().toLowerCase());
		}
		
		@Override
		protected SimpleResource doBuild() {
			SimpleResource resource = new SimpleResource(getName(), getType(), getPermissionChecker());
			return resource;
		}
	
	}

}
