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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * In-memory user account information storage.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 * @author Joel D'sa
 */
public class InMemoryUaaUserDatabase implements UaaUserDatabase {

    private final Map<String, UaaUser> users;
    private final Map<String, UaaUser> ids;

    public InMemoryUaaUserDatabase(Map<String, UaaUser> users) {
        this.users = new HashMap<>();
        this.ids = new HashMap<>();
        for (Map.Entry<String,UaaUser> entry : users.entrySet()) {
            this.ids.put(entry.getValue().getId(), entry.getValue());
            this.users.put(entry.getKey()+"-"+entry.getValue().getOrigin(), entry.getValue());
        }
    }

    @Override
    public UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException {

        UaaUser u = users.get(username+"-"+origin);
        if (u == null) {
            throw new UsernameNotFoundException("User " + username + " not found");
        }
        return u;
    }

    @Override
    public UaaUser retrieveUserById(String id) throws UsernameNotFoundException {
        UaaUser u = ids.get(id);
        if (u == null) {
            throw new UsernameNotFoundException("User ID:" + id + " not found");
        }
        return u;
    }

    public UaaUser updateUser(String userId, UaaUser user) throws UsernameNotFoundException {

        if (!ids.containsKey(userId)) {
            throw new UsernameNotFoundException("User " + userId + " not found");
        }
        ids.put(userId, user);
        return user;
    }

    public void clear() {
        this.ids.clear();
        this.users.clear();
    }

}
