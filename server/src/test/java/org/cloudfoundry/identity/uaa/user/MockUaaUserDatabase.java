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
package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.Date;

/**
 * @author Luke Taylor
 */
public class MockUaaUserDatabase extends InMemoryUaaUserDatabase {

    public MockUaaUserDatabase(String id, String name, String email, String givenName, String familyName) {
        super(Collections.singleton(createUser(id, name, email, givenName, familyName)));
    }

    private static UaaUser createUser(String id, String name, String email, String givenName, String familyName) {
        return new UaaUser(id, name, "", email, UaaAuthority.USER_AUTHORITIES, givenName, familyName,
                        new Date(), new Date(), OriginKeys.UAA, "externalId", false, IdentityZoneHolder.get().getId(), id, new Date());
    }
}
