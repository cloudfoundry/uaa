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
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.rest.Queryable;
import org.cloudfoundry.identity.uaa.rest.ResourceManager;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;


/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public interface ScimUserProvisioning extends ResourceManager<ScimUser>, Queryable<ScimUser> {

	public ScimUser createUser(ScimUser user, String password) throws InvalidPasswordException, InvalidScimResourceException;

	public boolean changePassword(String id, String oldPassword, String newPassword) throws ScimResourceNotFoundException;

}
