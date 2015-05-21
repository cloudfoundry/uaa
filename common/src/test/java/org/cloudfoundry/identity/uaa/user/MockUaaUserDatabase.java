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

import java.util.Date;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author Luke Taylor
 */
public class MockUaaUserDatabase implements UaaUserDatabase {
    UaaUser user;

    public MockUaaUserDatabase(String id, String name, String email, String givenName, String familyName) {
        user = new UaaUser(id, name, "", email, UaaAuthority.USER_AUTHORITIES, givenName, familyName,
                        new Date(), new Date(), Origin.UAA, "externalId", false, IdentityZoneHolder.get().getId(), id);
    }

    public MockUaaUserDatabase(String id, String name, String email, String givenName, String familyName,
                    Date createdAt, Date updatedAt) {
        user = new UaaUser(id, name, "", email, UaaAuthority.USER_AUTHORITIES, givenName, familyName,
                        createdAt, updatedAt, Origin.UAA, "externalId", false, IdentityZoneHolder.get().getId(), id);
    }

    @Override
    public UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException {
        if (user.getUsername().equals(username) && user.getOrigin().equals(origin)) {
            return user;
        }
        else {
            throw new UsernameNotFoundException(username);
        }
    }

    @Override
    public UaaUser retrieveUserById(String id) throws UsernameNotFoundException {
        if (user.getId().equals(id)) {
            return user;
        }
        else {
            throw new UsernameNotFoundException(id);
        }
    }

    public UaaUser updateUser(String userId, UaaUser user) throws UsernameNotFoundException {
        if (user.getId().equals(userId)) {
            this.user = user;
            return user;
        } else {
            throw new UsernameNotFoundException(userId);
        }
    }
}
