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
package org.cloudfoundry.identity.uaa.openid;

/**
 * <p>
 * Convenience object for collecting an rendering user info for the OpenId Connect endpoint.
 * </p>
 * <p>
 * Also defines constants for the OpenId Connect endpoint field names, so they can have a consistent naming convention and
 * share with other endpoints if needed.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
public abstract class UserInfo {

	/**
	 * A user's unique identifier - the thing that he remembers and types into an authentication prompt, not a system
	 * primary key.
	 */
	public static final String USER_ID = "user_id";

	/**
	 * A user's full name as he would prefer to see it formatted.
	 */
	public static final String NAME = "name";

	/**
	 * The user's primary email address.
	 */
	public static final String EMAIL = "email";

	/**
	 * The user's given name (i.e. first name in Western cultures).
	 */
	public static final String GIVEN_NAME = "given_name";

	/**
	 * The user's family name (i.e. surname).
	 */
	public static final String FAMILY_NAME = "family_name";

}
