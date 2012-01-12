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
package org.cloudfoundry.identity.uaa.security;

/**
 * Encapsulation of security context access for use within the application.
 *
 * Will be expanded as other requirements emerge.
 *
 * @author Luke Taylor
 */
public interface SecurityContextAccessor {

	/**
	 * Returns true if the current invocation is being made by
	 * a client, not by or on behalf of (in the oauth sense) an end user.
	 */
	boolean currentUserIsClient();

	String getCurrentUserId();
}
