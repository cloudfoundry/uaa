package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

@ExtendWith(PollutionPreventionExtension.class)
class ZoneAwareClientSecretPolicyValidatorTests {

    private ZoneAwareClientSecretPolicyValidator validator;

    private IdentityZone zone;

    private ClientSecretPolicy defaultPolicy = new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6);
    private ClientSecretPolicy strictPolicy = new ClientSecretPolicy(6, 10, 1, 1, 1, 1, 6);

    private static final String TEST_SECRET_1 = "";
    private static final String TEST_SECRET_2 = "testsecret";
    private static final String TEST_SECRET_3 = "VFNTTDEgMB4GA1UEAxMXZnNzLnN0YWdlLmdlY29tcGFueIb3DQEBAQUADDwDG6wkBY" +
            "sJSqbSYpw0c76bUB1x5e46eiroRZdU2BEWiQJ9yxV95gGNsdLH1105iubzc9dbxavGIYM9s/+qJRf6WfwDU7VQsURCqIN8eUtnPU808" +
            "PYjfBA4ucnwJ8wJ8er/8BhRVAfuleAU17WhURSsFZxfan5JxmMadsC+jQohUKiv6SFlPdxuxzuZijVwVgpWOUHO";

    private static final String TEST_SECRET_4 = "Tester1@";
    private static final String TEST_SECRET_5 = "Tester1";
    private static final String TEST_SECRET_6 = "Tester@";
    private static final String TEST_SECRET_7 = "tester@";
    private static final String TEST_SECRET_8 = "TESTER1@";

    @BeforeEach
    void setUp() {
        zone = new IdentityZone();
        IdentityZoneHolder.set(zone);
        validator = new ZoneAwareClientSecretPolicyValidator(defaultPolicy);
    }

    @Test
    void emptyClientSecret() {
        zone.getConfig().setClientSecretPolicy(defaultPolicy);
        validator.validate(TEST_SECRET_1);
    }

    @Test
    void default_policy_too_long_secret() {
        zone.getConfig().setClientSecretPolicy(defaultPolicy);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> validator.validate(TEST_SECRET_3));
    }

    @Test
    void defaultPolicy() {
        zone.getConfig().setClientSecretPolicy(defaultPolicy);
        validator.validate(TEST_SECRET_4);
        validator.validate(TEST_SECRET_2);
    }

    @Test
    void secretConformingToPolicy() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        validator.validate(TEST_SECRET_4);
    }

    @Test
    void secretMissingSpecialCharacter() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> validator.validate(TEST_SECRET_5));
    }

    @Test
    void secretMissingDigit() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> validator.validate(TEST_SECRET_6));
    }

    @Test
    void secretMissingUpperCaseCharacter() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> validator.validate(TEST_SECRET_7));
    }

    @Test
    void secretMissingLowerCaseCharacter() {
        zone.getConfig().setClientSecretPolicy(strictPolicy);
        assertThatExceptionOfType(InvalidClientSecretException.class).isThrownBy(() -> validator.validate(TEST_SECRET_8));
    }
}