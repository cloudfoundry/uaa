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

package org.cloudfoundry.identity.uaa.util;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class UaaTokenUtils {

    public static UaaTokenUtils instance() {
        return new UaaTokenUtils();
    }

    public Set<String> retainAutoApprovedScopes(Collection<String> requestedScopes, Set<String> autoApprovedScopes) {
        HashSet<String> result = new HashSet<>();
        Set<Pattern> autoApprovedScopePatterns = UaaStringUtils.constructWildcards(autoApprovedScopes);
        // Don't want to approve more than what's requested
        for (String scope : requestedScopes) {
            if (UaaStringUtils.matches(autoApprovedScopePatterns, scope)) {
                result.add(scope);
            }
        }
        return result;
    }
}
