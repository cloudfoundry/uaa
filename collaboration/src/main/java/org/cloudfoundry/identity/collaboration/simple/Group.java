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

import org.cloudfoundry.identity.collaboration.User;

/**
 * @author Dave Syer
 * 
 */
public class Group extends NamedEntity {

	private final Set<User> users;

	public Group(String name, Collection<User> users) {
		super(name);
		this.users = new HashSet<User>(users);
	}

	public Set<User> getUsers() {
		return Collections.unmodifiableSet(users);
	}

	public boolean contains(User user) {
		return users.contains(user);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((users == null) ? 0 : users.hashCode());
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
		Group other = (Group) obj;
		if (users == null) {
			if (other.users != null)
				return false;
		} else if (!users.equals(other.users))
			return false;
		return true;
	}

	public static class Builder {

		private String name;

		private Collection<User> users = new HashSet<User>();

		public Group build() {
			return new Group(name, users);
		}

		public Builder name(String name) {
			this.name = name;
			return this;
		}

		public Builder addUser(User user) {
			this.users.add(user);
			return this;
		}

	}

}
