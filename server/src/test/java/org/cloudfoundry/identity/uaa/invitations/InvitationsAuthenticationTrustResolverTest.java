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
import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;

import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class InvitationsAuthenticationTrustResolverTest {

    @Test
    public void testIsAnonymous() {
        InvitationsAuthenticationTrustResolver resolver = new InvitationsAuthenticationTrustResolver();
        AnonymousAuthenticationToken invitedAuthenticationToken = new AnonymousAuthenticationToken("key", new Object(),
                Collections.singletonList(UaaAuthority.UAA_INVITED));
        assertFalse(resolver.isAnonymous(invitedAuthenticationToken));

        AnonymousAuthenticationToken anonymousAuthenticationToken = new AnonymousAuthenticationToken("key", new Object(),
                Collections.singletonList(UaaAuthority.UAA_USER));
        assertTrue(resolver.isAnonymous(anonymousAuthenticationToken));
    }
}