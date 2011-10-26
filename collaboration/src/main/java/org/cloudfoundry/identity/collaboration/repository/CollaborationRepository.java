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

package org.cloudfoundry.identity.collaboration.repository;

import java.util.Set;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;

/**
 * @author Dave Syer
 *
 */
public interface CollaborationRepository {
	
	Org getOrg(String name) throws CollaborationModelException;
	
	Org addOrg(Org org);
	
	void removeOrg(Org org);
	
	Org renameOrg(Org org, String name);
	
	Org addProject(Org org, Project project);
	
	Org removeProject(Org org, Project project);
	
	Org updateProject(Org org, Project project);
	
	void removeUser(User user) throws CollaborationModelException;

	void removeProject(Project project) throws CollaborationModelException;

	Project getProject(String name) throws CollaborationModelException;

	void removeResource(Resource resource) throws CollaborationModelException;
	
	Set<String> findOrgNames(User user);

	Set<String> findProjectNames(User user);

}
