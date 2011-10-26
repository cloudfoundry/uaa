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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.Group;
import org.cloudfoundry.identity.collaboration.simple.GroupPermission;
import org.cloudfoundry.identity.collaboration.simple.PermissionChecker;

/**
 * @author Dave Syer
 *
 */
public abstract class GenericResourceBuilder<S extends GenericResourceBuilder<?,?>, T extends Resource> {

	private String name;
	
	private String type;

	private Collection<GroupPermission> permissions = new HashSet<GroupPermission>();

	private Map<Permission, Collection<User>> users = new HashMap<Permission, Collection<User>>();

	private final DirectPermissionChecker checker;
	
	public GenericResourceBuilder(DirectPermissionChecker checker) {
		this.checker = checker;
	}

	public T build() {
		T resource = doBuild();
		checker.addPermissions(resource, getPermissions());
		return resource;
	}

	protected abstract T doBuild();

	@SuppressWarnings("unchecked")
	public S name(String name) {
		this.name = name;
		return (S) this;
	}

	@SuppressWarnings("unchecked")
	public S type(String type) {
		this.type = type;
		return (S) this;
	}

	@SuppressWarnings("unchecked")
	public S addGroupPermissions(GroupPermission groupPermission) {
		this.permissions.add(groupPermission);
		return (S) this;
	}

	public S addUserPermissions(User user, Permission permission) {
		Collection<User> set = this.users.get(permission);
		if (set == null) {
			set = new HashSet<User>();
			this.users.put(permission, set);
		}
		set.add(user);
		@SuppressWarnings("unchecked")
		S result = (S) this;
		return result;
	}
	
	protected String getName() {
		return name;
	}
	
	protected String getType() {
		return type;
	}
	
	public PermissionChecker getPermissionChecker() {
		return checker;
	}
	
	protected Collection<GroupPermission> getPermissions() {
		Collection<GroupPermission> permissions = new HashSet<GroupPermission>(this.permissions);
		for (Permission key : users.keySet()) {
			Group group = new Group("_" + key, users.get(key));
			permissions.add(new GroupPermission(group, key));
		}
		return permissions;
	}

}
