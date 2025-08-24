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

package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

public class InvitationsAuthenticationTrustResolver implements AuthenticationTrustResolver {

    private final AuthenticationTrustResolver delegate = new AuthenticationTrustResolverImpl();

    @Override
    public boolean isAnonymous(Authentication authentication) {
        if (authentication != null && authentication.getAuthorities() != null && authentication.getAuthorities().contains(UaaAuthority.UAA_INVITED)) {
            return false;
        } else {
            return delegate.isAnonymous(authentication);
        }
    }

    @Override
    public boolean isRememberMe(Authentication authentication) {
        return delegate.isRememberMe(authentication);
    }
}
