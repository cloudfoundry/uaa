package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.mfa_provider.exception.InvalidMfaProviderConfigException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class GoogleMfaProviderConfigValidatorTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    public GoogleMfaProviderConfigValidator validator;

    @Before
    public void setup() {
        validator = new GoogleMfaProviderConfigValidator();
    }

    @Test
    public void testInvalidDigits() throws Exception{
        GoogleMfaProviderConfig config = new GoogleMfaProviderConfig();
        config.setDigits(-1);

        expectedException.expect(InvalidMfaProviderConfigException.class);
        expectedException.expectMessage("Digits must be greater than 0");
        validator.validate(config);
    }

    @Test
    public void testInvalidDuration() throws Exception{
        GoogleMfaProviderConfig config = new GoogleMfaProviderConfig();
        config.setDuration(-1);

        expectedException.expect(InvalidMfaProviderConfigException.class);
        expectedException.expectMessage("Duration must be greater than 0");
        validator.validate(config);
    }
}