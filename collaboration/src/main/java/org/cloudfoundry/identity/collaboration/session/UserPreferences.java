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
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.User;

/**
 * @author Dave Syer
 * 
 */
public class UserPreferences {

	private final User user;
	private final Org home;
	private final Project defaultProject;

	public UserPreferences(User user, Org home, Project defaultProject) {
		this.user = user;
		this.home = home;
		this.defaultProject = defaultProject;
		if (!home.getProjects().contains(defaultProject)) {
			throw new IllegalArgumentException("Org (" + home + ") does not contain project: "+defaultProject);
		}
	}

	public Org getHome() {
		return home;
	}

	public Project getDefaultProject() {
		return defaultProject;
	}

	public User getUser() {
		return user;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((defaultProject == null) ? 0 : defaultProject.hashCode());
		result = prime * result + ((home == null) ? 0 : home.hashCode());
		result = prime * result + ((user == null) ? 0 : user.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		UserPreferences other = (UserPreferences) obj;
		if (defaultProject == null) {
			if (other.defaultProject != null)
				return false;
		} else if (!defaultProject.equals(other.defaultProject))
			return false;
		if (home == null) {
			if (other.home != null)
				return false;
		} else if (!home.equals(other.home))
			return false;
		if (user == null) {
			if (other.user != null)
				return false;
		} else if (!user.equals(other.user))
			return false;
		return true;
	}

}
