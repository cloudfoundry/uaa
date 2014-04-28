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
package org.cloudfoundry.identity.uaa.scim;

import java.util.UUID;

import org.cloudfoundry.identity.uaa.scim.domain.common.ScimUserInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimUser;

/**
 * @author Dave Syer
 * 
 */
public class ScimUserTestFactory {

    public static ScimUserInterface getScimUser(String userName, String email, String givenName, String familyName) {
        ScimUserInterface user = new ScimUser(UUID.randomUUID().toString(), userName, givenName, familyName);
        if (email != null) {
            user.addEmail(email);
        }
        return user;
    }

}
