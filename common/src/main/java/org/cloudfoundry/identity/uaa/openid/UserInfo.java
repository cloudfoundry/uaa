/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
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
	 * A unique id which is never re-assigned.
	 */
	public static final String USER_ID = "user_id";

	/**
	 * A user's unique identifier - the thing that he remembers and types into an authentication prompt, not a system
	 * primary key.
	 */
	public static final String USER_NAME = "user_name";

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
