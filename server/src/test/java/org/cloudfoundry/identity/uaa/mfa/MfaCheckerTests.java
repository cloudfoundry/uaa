/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */

package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;

import org.junit.Before;
import org.junit.Test;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class MfaCheckerTests {

    private IdentityZone zone;
    private MfaChecker checker;
    private IdentityProviderProvisioning providerProvisioning;

    @Before
    public void setUp() throws Exception {
        providerProvisioning = mock(IdentityProviderProvisioning.class);
        zone = MultitenancyFixture.identityZone("id", "domain");
        checker = new MfaChecker(providerProvisioning);
    }

    @Test
    public void mfa_zone_enabled() {
        zone.getConfig().getMfaConfig().setEnabled(true);
        assertTrue(checker.isMfaEnabled(zone, UAA));
    }

    @Test
    public void mfa_zone_disabled() {
        zone.getConfig().getMfaConfig().setEnabled(false);
        assertFalse(checker.isMfaEnabled(zone, UAA));
    }
}