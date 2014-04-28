/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.dao.common;

import org.cloudfoundry.identity.uaa.rest.Queryable;
import org.cloudfoundry.identity.uaa.rest.ResourceManager;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserInterface;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public interface ScimUserProvisioning extends ResourceManager<ScimUserInterface>, Queryable<ScimUserInterface> {

    public ScimUserInterface createUser(ScimUserInterface user, String password) throws InvalidPasswordException,
                    InvalidScimResourceException;

    public boolean changePassword(String id, String oldPassword, String newPassword)
                    throws ScimResourceNotFoundException;

    public ScimUserInterface verifyUser(String id, int version) throws ScimResourceNotFoundException,
                    InvalidScimResourceException;

}
