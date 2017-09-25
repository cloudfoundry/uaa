package org.cloudfoundry.identity.uaa.mfa_provider;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import javax.xml.bind.ValidationException;

import static org.junit.Assert.assertTrue;

public class MfaProviderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void validateProviderNullConfig() throws ValidationException {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider config must be set");
        MfaProvider<GoogleMfaProviderConfig> provider = createValidGoogleMfaProvider()
                .setConfig(null);
        provider.validate();
    }

    @Test
    public void validateProviderEmptyName() throws ValidationException {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider name must be set");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName("");
        provider.validate();
    }

    @Test
    public void validateProviderInvalidNameTooLong() throws ValidationException {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider name invalid");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName(new RandomValueStringGenerator(256).generate());
        provider.validate();
    }
    @Test
    public void validateProviderInvalidNameWhitespace() throws ValidationException {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider name invalid");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName(" ");
        provider.validate();
    }

    @Test
    public void validateProviderInvalidNameSpecialChars() throws ValidationException {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider name invalid");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName("invalidName$");
        provider.validate();
    }


    @Test
    public void validateProviderNullType() throws ValidationException {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Provider type must be set");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setType(null);
        provider.validate();
    }

    @Test
    public void validateProviderActiveSetDefaultToTrue() {
        MfaProvider provider = createValidGoogleMfaProvider();
        assertTrue(provider.getActive());
    }

    private MfaProvider createValidGoogleMfaProvider() {
        MfaProvider<GoogleMfaProviderConfig> res = new MfaProvider();
        res.setName(new RandomValueStringGenerator(5).generate())
                .setConfig(createValidGoogleMfaConfig())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        return res;
    }

    private GoogleMfaProviderConfig createValidGoogleMfaConfig() {
        return new GoogleMfaProviderConfig()
                .setProviderDescription("config description")
                .setIssuer("current-zone")
                .setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256)
                .setDigits(42)
                .setDuration(13);
    }
}