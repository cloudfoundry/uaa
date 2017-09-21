package org.cloudfoundry.identity.uaa.mfa_provider;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider.GOOGLE_AUTH;
import static org.junit.Assert.assertTrue;

public class MfaProviderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void validateProviderInvalidConfig() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider config cannot be empty");
        MfaProvider provider = new MfaProvider().setActive(true).setName("Hey").setType(GOOGLE_AUTH);
        provider.validate();
    }

    @Test
    public void validateProviderDefaultConfig() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider config cannot be empty");
        MfaProvider provider = new MfaProvider().setActive(true).setName("Hey").setType(GOOGLE_AUTH);
        provider.validate();
    }

    @Test
    public void validateProviderInvalidType() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider type must be google-authenticator");
        MfaProvider provider = new MfaProvider().setType("TEST").setName("test-name");
        provider.validate();
    }

    @Test
    public void validateProviderInvalidName() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider name cannot be empty");
        MfaProvider provider = new MfaProvider().
                setType(GOOGLE_AUTH).
                setConfig("test-config");
        provider.validate();
    }

    @Test
    public void validateProviderActiveSetDefaultToTrue() {
        MfaProvider provider = new MfaProvider().
                setType(GOOGLE_AUTH).
                setConfig("test-config");
        assertTrue(provider.getActive());
    }
}