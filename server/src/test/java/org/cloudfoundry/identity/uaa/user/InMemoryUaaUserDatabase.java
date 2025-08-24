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
package org.cloudfoundry.identity.uaa.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

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
    private final Map<String, UserInfo> userInfo;

    public InMemoryUaaUserDatabase(Collection<UaaUser> users) {
        this.users = new HashMap<>();
        this.ids = new HashMap<>();
        this.userInfo = new HashMap<>();
        for (UaaUser user : users) {
            addUser(user);
        }
    }

    public void addUser(UaaUser user) {
        this.ids.put(user.getId(), user);
        this.users.put(user.getUsername() + "-" + user.getOrigin(), user);
    }

    @Override
    public UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException {

        UaaUser u = users.get(username + "-" + origin);
        if (u == null) {
            throw new UsernameNotFoundException("User " + username + " not found");
        }
        return u;
    }

    @Override
    public UaaUserPrototype retrieveUserPrototypeByName(String username, String origin) throws UsernameNotFoundException {
        return new UaaUserPrototype(retrieveUserByName(username, origin));
    }

    @Override
    public UaaUser retrieveUserById(String id) throws UsernameNotFoundException {
        UaaUser u = ids.get(id);
        if (u == null) {
            throw new UsernameNotFoundException("User ID:" + id + " not found");
        }
        return u;
    }

    @Override
    public UaaUserPrototype retrieveUserPrototypeById(String id) throws UsernameNotFoundException {
        return new UaaUserPrototype(retrieveUserById(id));
    }

    @Override
    public UaaUser retrieveUserByEmail(String email, String origin) throws UsernameNotFoundException {
        return users.values().stream().filter(u -> origin.equalsIgnoreCase(u.getOrigin()) && email.equalsIgnoreCase(u.getEmail())).findAny().orElse(null);
    }

    @Override
    public UaaUserPrototype retrieveUserPrototypeByEmail(String email, String origin) throws UsernameNotFoundException {
        return new UaaUserPrototype(retrieveUserByEmail(email, origin));
    }

    @Override
    public UserInfo getUserInfo(String id) {
        return userInfo.get(id);
    }

    @Override
    public UserInfo storeUserInfo(String id, UserInfo i) {
        UserInfo info = new UserInfo()
                .setUserAttributes(i.getUserAttributes())
                .setRoles(i.getRoles());
        this.userInfo.put(id, info);
        return i;
    }

    @Override
    public void updateLastLogonTime(String id) {
        retrieveUserById(id).setLastLogonTime(System.currentTimeMillis());
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
