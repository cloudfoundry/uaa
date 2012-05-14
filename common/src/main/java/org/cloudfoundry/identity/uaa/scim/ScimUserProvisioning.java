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

import java.util.List;


/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public interface ScimUserProvisioning {

	public ScimUser retrieveUser(String id) throws UserNotFoundException;

	public List<ScimUser> retrieveUsers();

	public List<ScimUser> retrieveUsers(String filter);

	public List<ScimUser> retrieveUsers(String filter, String sortBy, boolean ascending);

	public ScimUser createUser(ScimUser user, String password) throws InvalidPasswordException, InvalidUserException;

	public ScimUser updateUser(String id, ScimUser user) throws InvalidUserException, UserNotFoundException;

	public boolean changePassword(String id, String oldPassword, String newPassword) throws UserNotFoundException;

	public ScimUser removeUser(String id, int version) throws UserNotFoundException;

}
