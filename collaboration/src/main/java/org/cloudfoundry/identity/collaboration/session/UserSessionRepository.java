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

import java.util.Set;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.User;

/**
 * @author Dave Syer
 *
 */
public interface UserSessionRepository {

	boolean hasUserPreferences(User user);
	
	UserPreferences loadUserPreferences(User user);
	
	UserPreferences addUserPreferences(UserPreferences userPreferences);
	
	UserPreferences updateUserPreferences(UserPreferences userPreferences);
	
	void removeUserPreferences(User user);
	
	boolean hasUserSession(User user);
	
	Set<Session> getUserSessions(User user);
	
	Set<Session> getDelegatedSessions(User master);
	
	Session startUserSession(User user) throws UserPreferencesNotFoundException;
	
	Session startUserSession(User user, Org org) throws UserPreferencesNotFoundException;
	
	Session startUserSession(User user, Org org, Project project);
	
	Session startDelegatedSession(User master, User puppet, Org org, Project project);
	
	void endUserSession(Session userSession) throws SessionNotFoundException;
	
}
