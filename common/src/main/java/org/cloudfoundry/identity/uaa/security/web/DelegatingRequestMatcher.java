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

package org.cloudfoundry.identity.uaa.security.web;

import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Luke Taylor
 */
public class DelegatingRequestMatcher implements RequestMatcher {
    private final List<RequestMatcher> matchers;

    public DelegatingRequestMatcher(List<RequestMatcher> matchers) {
        this.matchers = new ArrayList<>(matchers);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        for (RequestMatcher m : matchers) {
            if (m.matches(request)) {
                return true;
            }
        }

        return false;
    }
}
