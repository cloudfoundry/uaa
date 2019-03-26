package org.cloudfoundry.identity.uaa.mfa;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;

class MfaCheckerTests {

    private IdentityZone identityZone;
    private MfaChecker mfaChecker;
    private IdentityProviderProvisioning identityProviderProvisioning;

    @BeforeEach
    void setUp() {
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        identityZone = MultitenancyFixture.identityZone("id", "domain");
        mfaChecker = new MfaChecker(identityProviderProvisioning);
    }

    @Test
    void isMfaEnabled_WhenEnabled() {
        identityZone.getConfig().getMfaConfig().setEnabled(true);
        assertTrue(mfaChecker.isMfaEnabled(identityZone, UAA));
    }

    @Test
    void isMfaEnabled_WhenDisabled() {
        identityZone.getConfig().getMfaConfig().setEnabled(false);
        assertFalse(mfaChecker.isMfaEnabled(identityZone, UAA));
    }

    @Test
    void mfaIsRequiredWhenCorrectOriginsAreConfigured() {
        identityZone.getConfig().getMfaConfig().setIdentityProviders(
                Lists.newArrayList("uaa", "ldap"));

        assertThat(mfaChecker.isRequired(identityZone, UAA), is(true));
        assertThat(mfaChecker.isRequired(identityZone, "other"), is(false));
    }

    @Test
    void mfaConfig_getIdentityProviders_returnsUaaAndLdap() {
        assertThat(MfaConfig.DEFAULT_MFA_IDENTITY_PROVIDERS, is(Arrays.asList(UAA, LDAP)));

        identityZone.getConfig().getMfaConfig().setIdentityProviders(
                Lists.newArrayList());

        assertThat(mfaChecker.isRequired(identityZone, UAA), is(true));
        assertThat(mfaChecker.isRequired(identityZone, LDAP), is(true));
        assertThat(mfaChecker.isRequired(identityZone, SAML), is(false));
        assertThat(mfaChecker.isRequired(identityZone, "other"), is(false));
    }
}