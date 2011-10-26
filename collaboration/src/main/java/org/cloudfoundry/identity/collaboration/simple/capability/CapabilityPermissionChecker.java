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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.Group;
import org.cloudfoundry.identity.collaboration.simple.GroupPermission;
import org.cloudfoundry.identity.collaboration.simple.PermissionChecker;

/**
 * @author Dave Syer
 * 
 */
public class CapabilityPermissionChecker implements PermissionChecker {

	private static final DynamicDefaultPermissionChecker DEFAULT_PERMISSION_CHECKER = new DynamicDefaultPermissionChecker();

	private Map<Org, OrgCapabilityPermissionChecker> checkers = new HashMap<Org, OrgCapabilityPermissionChecker>();

	private Map<Resource, Org> orgs = new HashMap<Resource, Org>();

	public void addCapability(Org org, Group group, Capability capability) {
		OrgCapabilityPermissionChecker checker = getChecker(org);
		checker.addCapability(group, capability);
	}

	public void addCapability(Org org, User user, Capability capability) {
		Group group = new Group("_" + capability.getName(), Collections.singleton(user));
		OrgCapabilityPermissionChecker checker = getChecker(org);
		checker.addCapability(group, capability);
	}

	@Override
	public boolean isPermitted(Resource resource, User user, Permission permission) {
		return getChecker(resource, user).isPermitted(resource, user, permission);
	}

	private PermissionChecker getChecker(Resource resource, User user) {
		if (!orgs.containsKey(resource)) {
			return DEFAULT_PERMISSION_CHECKER;
		}
		return getChecker(orgs.get(resource));
	}

	private OrgCapabilityPermissionChecker getChecker(Org org) {
		OrgCapabilityPermissionChecker checker = checkers.get(org);
		if (checker == null) {
			checker = new OrgCapabilityPermissionChecker(org);
			checkers.put(org, checker);
		}
		if (!orgs.containsKey(org)) {
			orgs.put(org, org);
			for (Project project : org.getProjects()) {
				orgs.put(project, org);
			}
			for (Resource resource : org.getResources()) {
				orgs.put(resource, org);
			}
		}
		return checker;
	}

	private static class OrgCapabilityPermissionChecker implements PermissionChecker {

		private final Map<Resource, Set<GroupPermission>> resourcePermisions = new HashMap<Resource, Set<GroupPermission>>();

		private final Map<Resource, Resource> parents = new HashMap<Resource, Resource>();

		private final Org org;

		public OrgCapabilityPermissionChecker(Org org) {
			this.org = org;
		}

		public void addCapability(Group group, Capability capability) {
			updatePermissions(group, capability);
		}

		private void updatePermissions(Group group, Capability capability) {
			for (Resource resource : capability.findMatchingResources(org)) {
				addPermissions(resource, capability.getGroupPermission(group));
			}
		}

		private void addPermissions(Resource resource, GroupPermission permission) {
			if (resource instanceof Project) {
				for (Resource child : ((Project) resource).getResources()) {
					parents.put(child, resource);
				}
			}
			if (resource instanceof Org) {
				for (Resource child : ((Org) resource).getProjects()) {
					parents.put(child, resource);
					for (Resource baby : ((Project) child).getResources()) {
						parents.put(baby, child);
					}
				}
			}
			Set<GroupPermission> permissions = resourcePermisions.get(resource);
			if (permissions == null) {
				permissions = new HashSet<GroupPermission>();
				resourcePermisions.put(resource, permissions);
			}
			permissions.add(permission);
			resourcePermisions.put(resource, permissions);
		}

		private GroupPermission getPermissionIfPresent(Resource resource, User user) {
			GroupPermission candidate = null;
			Set<GroupPermission> permissions = resourcePermisions.get(resource);
			if (permissions == null) {
				return null;
			}
			for (GroupPermission permission : permissions) {
				Object subject = permission.getGroup();
				if (user.equals(subject)) {
					candidate = replaceIfContains(candidate, permission);
				}
				if ((subject instanceof Group) && ((Group) subject).contains(user)) {
					candidate = replaceIfContains(candidate, permission);
				}
			}
			return candidate;
		}

		private GroupPermission replaceIfContains(GroupPermission candidate, GroupPermission permission) {
			return candidate == null || permission.getPermission().contains(candidate.getPermission()) ? permission
					: candidate;
		}

		@Override
		public boolean isPermitted(Resource resource, User user, Permission permission) {
			GroupPermission member = getPermissionIfPresent(resource, user);
			if (member != null && member.getPermission().contains(permission)) {
				return true;
			}
			if (parents.containsKey(resource)) {
				Resource parent = parents.get(resource);
				return isPermitted(parent, user, permission);
			}
			return false;
		}

	}

}
