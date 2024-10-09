/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.cloudfoundry.identity.uaa.resources.ResourceManager;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import java.util.List;


public interface ScimUserProvisioning extends ResourceManager<ScimUser>, Queryable<ScimUser> {

    ScimUser createUser(ScimUser user, String password, String zoneId) throws InvalidPasswordException, InvalidScimResourceException;

    List<ScimUser> retrieveByEmailAndZone(String email, String origin, String zoneId);

    List<ScimUser> retrieveByUsernameAndZone(String username, String zoneId);

    /**
     * Retrieve all users that satisfy the given SCIM filter and stem from active IdPs.
     */
    List<ScimUser> retrieveByScimFilterOnlyActive(
            String filter,
            String sortBy,
            boolean ascending,
            String zoneId
    );

    List<ScimUser> retrieveByUsernameAndOriginAndZone(String username, String origin, String zoneId);

    void changePassword(String id, String oldPassword, String newPassword, String zoneId) throws ScimResourceNotFoundException;

    void updatePasswordChangeRequired(String userId, boolean passwordChangeRequired, String zoneId) throws ScimResourceNotFoundException;

    ScimUser verifyUser(String id, int version, String zoneId) throws ScimResourceNotFoundException, InvalidScimResourceException;

    boolean checkPasswordMatches(String id, CharSequence password, String zoneId) throws ScimResourceNotFoundException;

    boolean checkPasswordChangeIndividuallyRequired(String id, String zoneId) throws ScimResourceNotFoundException;

    void updateLastLogonTime(String id, String zoneId);
}

