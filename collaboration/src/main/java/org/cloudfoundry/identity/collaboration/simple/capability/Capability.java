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

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.simple.Group;
import org.cloudfoundry.identity.collaboration.simple.GroupPermission;
import org.cloudfoundry.identity.collaboration.simple.NamedEntity;

/**
 * @author Dave Syer
 * 
 */
public class Capability extends NamedEntity {

	private final Permission permission;

	private final String pattern;

	public Capability(String name, String pattern, Permission permission) {
		super(name);
		this.pattern = normalize(pattern);
		this.permission = permission;
	}

	private String normalize(String path) {
		path = path.trim();
		if (path.startsWith("/")) {
			return normalize(path.substring(1));
		}
		if (path.endsWith("/")) {
			return normalize(path.substring(path.length() - 1));
		}
		return path;
	}

	public GroupPermission getGroupPermission(Group group) {
		if (group != null) {
			return new GroupPermission(group, permission);
		}
		return new GroupPermission(group, permission);
	}

	public Collection<Resource> findMatchingResources(Org org) {
		if (pattern.equals("")) {
			return Collections.<Resource> singleton(org);
		}
		HashSet<Resource> resources = new HashSet<Resource>();
		String[] paths = pattern.split("/");
		for (Project project : org.getProjects()) {
			if (simpleMatch(paths[0], project.getName())) {
				if (paths.length == 1) {
					resources.add(project);
					continue;
				}
				for (Resource resource : project.getResources()) {
					for (int i = 1; i < paths.length; i += 2) {
						if (simpleMatch(paths[i], resource.getType())) {
							if (paths.length == i + 1) {
								resources.add(resource);
								continue;
							}
							if (simpleMatch(paths[i + 1], resource.getName())) {
								resources.add(resource);

							}
						}
					}
				}
			}
		}
		return resources;
	}

	/**
	 * Match a String against the given pattern, supporting the following simple pattern styles: "xxx*", "*xxx", "*xxx*"
	 * and "xxx*yyy" matches (with an arbitrary number of pattern parts), as well as direct equality.
	 * @param pattern the pattern to match against
	 * @param str the String to match
	 * @return whether the String matches the given pattern
	 */
	public static boolean simpleMatch(String pattern, String str) {
		if (pattern == null || str == null) {
			return false;
		}
		int firstIndex = pattern.indexOf('*');
		if (firstIndex == -1) {
			return pattern.equals(str);
		}
		if (firstIndex == 0) {
			if (pattern.length() == 1) {
				return true;
			}
			int nextIndex = pattern.indexOf('*', firstIndex + 1);
			if (nextIndex == -1) {
				return str.endsWith(pattern.substring(1));
			}
			String part = pattern.substring(1, nextIndex);
			int partIndex = str.indexOf(part);
			while (partIndex != -1) {
				if (simpleMatch(pattern.substring(nextIndex), str.substring(partIndex + part.length()))) {
					return true;
				}
				partIndex = str.indexOf(part, partIndex + 1);
			}
			return false;
		}
		return (str.length() >= firstIndex && pattern.substring(0, firstIndex).equals(str.substring(0, firstIndex)) && simpleMatch(
				pattern.substring(firstIndex), str.substring(firstIndex)));
	}

}
