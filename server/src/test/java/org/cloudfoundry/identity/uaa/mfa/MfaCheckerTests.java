package org.cloudfoundry.identity.uaa.mfa;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;
import java.util.stream.Stream;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class MfaCheckerTests {

    private IdentityZone identityZone;
    private MfaChecker mfaChecker;
    private IdentityZoneProvisioning mockIdentityZoneProvisioning;
    private RandomValueStringGenerator randomValueStringGenerator;

    @BeforeEach
    void setUp() {
        randomValueStringGenerator = new RandomValueStringGenerator();

        identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());

        mockIdentityZoneProvisioning = mock(IdentityZoneProvisioning.class);
        when(mockIdentityZoneProvisioning.retrieve(any())).thenReturn(identityZone);

        mfaChecker = new MfaChecker(mockIdentityZoneProvisioning);
    }

    static class BooleanArgumentsProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                    Arguments.of(true),
                    Arguments.of(false)
            );
        }
    }

    @ParameterizedTest
    @ArgumentsSource(BooleanArgumentsProvider.class)
    void isMfaEnabled(final boolean isMfaEnabled) {
        identityZone.getConfig().getMfaConfig().setEnabled(isMfaEnabled);
        assertEquals(isMfaEnabled, mfaChecker.isMfaEnabled(identityZone));
    }

    @ParameterizedTest
    @ArgumentsSource(BooleanArgumentsProvider.class)
    void isMfaEnabledForZoneId(final boolean isMfaEnabled) {
        final String zoneId = randomValueStringGenerator.generate();
        identityZone.getConfig().getMfaConfig().setEnabled(isMfaEnabled);
        assertEquals(isMfaEnabled, mfaChecker.isMfaEnabledForZoneId(zoneId));

        verify(mockIdentityZoneProvisioning).retrieve(zoneId);
    }

    @Test
    void mfaIsRequiredWhenCorrectOriginsAreConfigured() {
        final String randomIdp = randomValueStringGenerator.generate();
        identityZone.getConfig().getMfaConfig().setIdentityProviders(
                Lists.newArrayList("uaa", "george", randomIdp));

        assertThat(mfaChecker.isRequired(identityZone, "uaa"), is(true));
        assertThat(mfaChecker.isRequired(identityZone, "george"), is(true));
        assertThat(mfaChecker.isRequired(identityZone, randomIdp), is(true));

        assertThat(mfaChecker.isRequired(identityZone, "other"), is(false));
        assertThat(mfaChecker.isRequired(identityZone, null), is(false));
        assertThat(mfaChecker.isRequired(identityZone, ""), is(false));
        assertThat(mfaChecker.isRequired(identityZone, randomValueStringGenerator.generate()), is(false));
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