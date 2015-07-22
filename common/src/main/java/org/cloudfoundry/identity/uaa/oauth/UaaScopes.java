/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;


import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class UaaScopes {


    private List<String> scopes = Collections.unmodifiableList(Arrays.asList(
        "zones.read",
        "zones.write",
        "zones.*.admin",
        "zones.*.clients.admin",
        "zones.*.clients.read",
        "zones.*.idps.read",
        "idps.read",
        "idps.write",
        "clients.admin",
        "clients.write",
        "clients.read",
        "clients.secret",
        "scim.write",
        "scim.read",
        "scim.create",
        "scim.userids",
        "scim.zones",
        "groups.update",
        "password.write",
        "oauth.login"
    ));

    private Set<Pattern> regExPatterns = UaaStringUtils.constructWildcards(new HashSet<>(scopes));

    public List<String> getUaaScopes() {
        return scopes;
    }

    public List<GrantedAuthority> getUaaAuthorities() {
        List<GrantedAuthority> result = new LinkedList<>();
        for (String s : getUaaScopes()) {
            result.add(new SimpleGrantedAuthority(s));

        }
        return result;
    }

    public boolean isWildcardScope(String scope) {
        return UaaStringUtils.containsWildcard(scope);
    }

    public boolean isWildcardScope(GrantedAuthority authority) {
        return isWildcardScope(authority.getAuthority());
    }

    public boolean isUaaScope(String scope) {
        return UaaStringUtils.matches(regExPatterns, scope);
    }

    public boolean isUaaScope(GrantedAuthority authority) {
        return isUaaScope(authority.getAuthority());
    }

}
