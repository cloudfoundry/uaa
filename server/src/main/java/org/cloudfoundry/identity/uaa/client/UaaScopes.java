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

package org.cloudfoundry.identity.uaa.client;


import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes.UAA_SCOPES;

public class UaaScopes {


    private final Set<Pattern> regExPatterns = UaaStringUtils.constructWildcards(new HashSet<>(UAA_SCOPES));

    public List<String> getUaaScopes() {
        return UAA_SCOPES;
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
