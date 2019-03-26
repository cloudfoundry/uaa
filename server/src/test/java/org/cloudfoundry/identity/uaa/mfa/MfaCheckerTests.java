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

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class MfaCheckerTests {

    private IdentityZone identityZone;
    private MfaChecker mfaChecker;
    private IdentityProviderProvisioning identityProviderProvisioning;

    @Before
    public void setUp() throws Exception {
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        identityZone = MultitenancyFixture.identityZone("id", "domain");
        mfaChecker = new MfaChecker(identityProviderProvisioning);
    }

    @Test
    public void isMfaEnabled_WhenEnabled() {
        identityZone.getConfig().getMfaConfig().setEnabled(true);
        assertTrue(mfaChecker.isMfaEnabled(identityZone, UAA));
    }

    @Test
    public void isMfaEnabled_WhenDisabled() {
        identityZone.getConfig().getMfaConfig().setEnabled(false);
        assertFalse(mfaChecker.isMfaEnabled(identityZone, UAA));
    }

    @Test
    public void mfaIsRequiredWhenCorrectOriginsAreConfigured() {
        identityZone.getConfig().getMfaConfig().setIdentityProviders(
                Lists.newArrayList("uaa", "ldap"));

        assertThat(mfaChecker.isRequired(identityZone, UAA), is(true));
        assertThat(mfaChecker.isRequired(identityZone, "other"), is(false));
    }

    @Test
    public void mfaConfig_getIdentityProviders_returnsUaaAndLdap() {
        assertThat(MfaConfig.DEFAULT_MFA_IDENTITY_PROVIDERS, is(Arrays.asList(UAA, LDAP)));

        identityZone.getConfig().getMfaConfig().setIdentityProviders(
                Lists.newArrayList());

        assertThat(mfaChecker.isRequired(identityZone, UAA), is(true));
        assertThat(mfaChecker.isRequired(identityZone, LDAP), is(true));
        assertThat(mfaChecker.isRequired(identityZone, SAML), is(false));
        assertThat(mfaChecker.isRequired(identityZone, "other"), is(false));
    }
}