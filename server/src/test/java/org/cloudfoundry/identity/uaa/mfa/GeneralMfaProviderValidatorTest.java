package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaProviderException;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import javax.xml.bind.ValidationException;

import static org.junit.Assert.assertEquals;

public class GeneralMfaProviderValidatorTest {

    GeneralMfaProviderValidator validator;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setup() {
        validator = new GeneralMfaProviderValidator();
    }

    @Test
    public void validateProviderNullConfig() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider config is required");
        MfaProvider<GoogleMfaProviderConfig> provider = createValidGoogleMfaProvider()
                .setConfig(null);
        validator.validate(provider);
    }

    @Test
    public void validateProviderConfigWithInvalidIssuer() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider config contains an invalid issuer. Issuer must not contain a colon");
        MfaProvider<GoogleMfaProviderConfig> provider = createValidGoogleMfaProvider()
                .setConfig(createValidGoogleMfaConfig().setIssuer("invalid:issuer"));
        validator.validate(provider);
    }

    @Test
    public void validateProviderConfigWithMissingIssuer() throws ValidationException {
        MfaProvider<GoogleMfaProviderConfig> provider = createValidGoogleMfaProvider()
                .setConfig(createValidGoogleMfaConfig().setIssuer(null));
        validator.validate(provider);
    }

    @Test
    public void validateProviderEmptyName() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider name is required");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName("");
        validator.validate(provider);
    }

    @Test
    public void validateProviderInvalidNameTooLong() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider name cannot be longer than 256 characters");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName(new RandomValueStringGenerator(257).generate());
        validator.validate(provider);
    }
    @Test
    public void validateProviderInvalidName() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider name is required");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName(" ");
        validator.validate(provider);
    }

    @Test
    public void validateProviderWhitespaceInName() {
        String name = "This is a valid name";
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName(name);
        validator.validate(provider);
    }

    @Test
    public void validateProviderTrimsName() {
        String name = "   This is also a valid name    ";
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName(name);
        provider.setName(" " + name + " ");
        validator.validate(provider);
        assertEquals(name.trim(), provider.getName());
    }

    @Test
    public void validateProviderInvalidNameSpecialChars() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider name must be alphanumeric");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setName("invalidName$");
        validator.validate(provider);
    }


    @Test
    public void validateProviderNullType() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider type is required. Must be one of " + MfaProvider.MfaProviderType.getStringValues());
        MfaProvider provider = createValidGoogleMfaProvider()
                .setType(null);
        validator.validate(provider);
    }

    @Test
    public void validateProviderEmptyZone() throws ValidationException {
        expectedException.expect(InvalidMfaProviderException.class);
        expectedException.expectMessage("Provider must belong to a zone");
        MfaProvider provider = createValidGoogleMfaProvider()
                .setIdentityZoneId("");
        validator.validate(provider);
    }

    private MfaProvider createValidGoogleMfaProvider() {
        MfaProvider<GoogleMfaProviderConfig> res = new MfaProvider();
        res.setName(new RandomValueStringGenerator(5).generate())
                .setConfig(createValidGoogleMfaConfig())
                .setIdentityZoneId(IdentityZone.getUaaZoneId())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        return res;
    }

    private GoogleMfaProviderConfig createValidGoogleMfaConfig() {
        return (GoogleMfaProviderConfig) new GoogleMfaProviderConfig()
                .setProviderDescription("config description")
                .setIssuer("current-zone");
    }
}