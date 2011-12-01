/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.scim;

import java.util.Collection;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public interface ScimUserProvisioning {

	public ScimUser retrieveUser(String id) throws UserNotFoundException;

	public Collection<ScimUser> retrieveUsers();

	public Collection<ScimUser> retrieveUsers(String filter);

	public ScimUser createUser(ScimUser user, String password) throws InvalidPasswordException, InvalidUserException;

	public ScimUser updateUser(String id, ScimUser user) throws InvalidUserException, UserNotFoundException;

	public ScimUser removeUser(String id, int version) throws UserNotFoundException;

}
